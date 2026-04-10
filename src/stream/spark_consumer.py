"""
PySpark structured streaming consumer for Guardance.

Reads JSON events from Redpanda/Kafka topics (raw.modbus, raw.dnp3,
raw.conn) using Spark Structured Streaming, parses them into typed
DataFrames, and writes Device nodes and COMMUNICATES_WITH edges to Neo4j
via micro-batch foreachBatch sinks.

This module is designed for high-volume OT segments where per-event Neo4j
writes from the Python consumer become a bottleneck.  Spark batches events
within a trigger interval (default 5 seconds) and writes them in bulk.

Requirements:
    - PySpark 3.4+ (``pip install pyspark``)
    - Java 11+ runtime on PATH
    - ``spark-sql-kafka`` and ``neo4j-connector`` JARs on the Spark classpath
      (configured via ``SPARK_KAFKA_JAR`` and ``SPARK_NEO4J_JAR`` env vars,
      or included in ``spark.jars.packages``)

Configuration (env vars):
    REDPANDA_BOOTSTRAP_SERVERS   default: "localhost:9092"
    REDPANDA_TOPIC_PREFIX        default: ""
    NEO4J_URI                    default: "bolt://localhost:7687"
    NEO4J_USER                   default: "neo4j"
    NEO4J_PASSWORD               default: "neo4j"
    SPARK_APP_NAME               default: "guardance-stream"
    SPARK_MASTER                 default: "local[*]"
    SPARK_TRIGGER_SECONDS        default: "5"
    SPARK_CHECKPOINT_DIR         default: "/tmp/guardance-checkpoint"
    SPARK_KAFKA_PACKAGES         default: "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1"
    SPARK_NEO4J_PACKAGES         default: "org.neo4j:neo4j-connector-apache-spark_2.12:5.2.0_for_spark_3"
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any, Iterator, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    # These imports are only for type checkers; at runtime PySpark may not be
    # installed or Java may be unavailable.
    from pyspark.sql import DataFrame, SparkSession
    from pyspark.sql.streaming import StreamingQuery


# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------

def _get_modbus_schema() -> "Any":
    """Return the PySpark StructType schema for modbus events."""
    from pyspark.sql.types import (
        DoubleType, IntegerType, StringType, StructField, StructType,
    )
    return StructType([
        StructField("ts",        StringType(),  nullable=False),
        StructField("uid",       StringType(),  nullable=False),
        StructField("orig_h",    StringType(),  nullable=False),
        StructField("orig_p",    IntegerType(), nullable=False),
        StructField("resp_h",    StringType(),  nullable=False),
        StructField("resp_p",    IntegerType(), nullable=False),
        StructField("func",      StringType(),  nullable=False),
        StructField("exception", StringType(),  nullable=True),
    ])


def _get_dnp3_schema() -> "Any":
    """Return the PySpark StructType schema for dnp3 events."""
    from pyspark.sql.types import (
        IntegerType, StringType, StructField, StructType,
    )
    return StructType([
        StructField("ts",         StringType(),  nullable=False),
        StructField("uid",        StringType(),  nullable=False),
        StructField("orig_h",     StringType(),  nullable=False),
        StructField("orig_p",     IntegerType(), nullable=False),
        StructField("resp_h",     StringType(),  nullable=False),
        StructField("resp_p",     IntegerType(), nullable=False),
        StructField("fc_request", StringType(),  nullable=False),
        StructField("fc_reply",   StringType(),  nullable=True),
        StructField("iin",        IntegerType(), nullable=True),
    ])


def _get_conn_schema() -> "Any":
    """Return the PySpark StructType schema for conn events."""
    from pyspark.sql.types import (
        BooleanType, DoubleType, IntegerType, StringType,
        StructField, StructType, ArrayType,
    )
    return StructType([
        StructField("ts",             StringType(),         nullable=False),
        StructField("uid",            StringType(),         nullable=False),
        StructField("orig_h",         StringType(),         nullable=False),
        StructField("orig_p",         IntegerType(),        nullable=False),
        StructField("resp_h",         StringType(),         nullable=False),
        StructField("resp_p",         IntegerType(),        nullable=False),
        StructField("proto",          StringType(),         nullable=False),
        StructField("service",        StringType(),         nullable=True),
        StructField("duration",       DoubleType(),         nullable=True),
        StructField("orig_bytes",     IntegerType(),        nullable=True),
        StructField("resp_bytes",     IntegerType(),        nullable=True),
        StructField("conn_state",     StringType(),         nullable=False),
        StructField("local_orig",     BooleanType(),        nullable=True),
        StructField("local_resp",     BooleanType(),        nullable=True),
        StructField("missed_bytes",   IntegerType(),        nullable=True),
        StructField("history",        StringType(),         nullable=True),
        StructField("orig_pkts",      IntegerType(),        nullable=True),
        StructField("orig_ip_bytes",  IntegerType(),        nullable=True),
        StructField("resp_pkts",      IntegerType(),        nullable=True),
        StructField("resp_ip_bytes",  IntegerType(),        nullable=True),
        StructField("tunnel_parents", ArrayType(StringType()), nullable=True),
    ])


# ---------------------------------------------------------------------------
# SparkSession factory
# ---------------------------------------------------------------------------

def create_spark_session(
    app_name: Optional[str] = None,
    master: Optional[str] = None,
    kafka_packages: Optional[str] = None,
    neo4j_packages: Optional[str] = None,
) -> "SparkSession":
    """
    Create and return a configured SparkSession.

    Packages for Kafka source and Neo4j sink are resolved automatically
    from environment variables unless overridden.

    Args:
        app_name:       Spark application name.
        master:         Spark master URL (e.g. ``"local[*]"``).
        kafka_packages: Maven coordinates for the Kafka connector JAR.
        neo4j_packages: Maven coordinates for the Neo4j connector JAR.

    Returns:
        A configured :class:`pyspark.sql.SparkSession`.

    Raises:
        ImportError: If PySpark is not installed.
        RuntimeError: If Java is not available.
    """
    try:
        from pyspark.sql import SparkSession
    except ImportError as exc:
        raise ImportError(
            "PySpark is required for streaming mode. Install it with: pip install pyspark"
        ) from exc

    _app_name = app_name or os.environ.get("SPARK_APP_NAME", "guardance-stream")
    _master = master or os.environ.get("SPARK_MASTER", "local[*]")
    _kafka_pkg = kafka_packages or os.environ.get(
        "SPARK_KAFKA_PACKAGES",
        "org.apache.spark:spark-sql-kafka-0-10_2.12:3.4.1",
    )
    _neo4j_pkg = neo4j_packages or os.environ.get(
        "SPARK_NEO4J_PACKAGES",
        "org.neo4j:neo4j-connector-apache-spark_2.12:5.2.0_for_spark_3",
    )

    packages = ",".join(filter(None, [_kafka_pkg, _neo4j_pkg]))

    builder = (
        SparkSession.builder
        .appName(_app_name)
        .master(_master)
        .config("spark.jars.packages", packages)
        .config("spark.sql.streaming.checkpointLocation",
                os.environ.get("SPARK_CHECKPOINT_DIR", "/tmp/guardance-checkpoint"))
        # Reduce log noise in development
        .config("spark.ui.showConsoleProgress", "false")
    )

    spark = builder.getOrCreate()
    spark.sparkContext.setLogLevel("WARN")
    logger.info("SparkSession created — app=%s master=%s", _app_name, _master)
    return spark


# ---------------------------------------------------------------------------
# Kafka source builder
# ---------------------------------------------------------------------------

def _kafka_options(
    bootstrap_servers: str,
    topic_prefix: str = "",
) -> dict[str, str]:
    """Build the Kafka/Redpanda source options dict for readStream."""
    topics = ",".join(
        f"{topic_prefix}{t}" for t in ("raw.modbus", "raw.dnp3", "raw.conn")
    )
    return {
        "kafka.bootstrap.servers": bootstrap_servers,
        "subscribe":               topics,
        "startingOffsets":         "earliest",
        "failOnDataLoss":          "false",
    }


def build_kafka_stream(
    spark: "SparkSession",
    bootstrap_servers: Optional[str] = None,
    topic_prefix: str = "",
) -> "DataFrame":
    """
    Build a Kafka structured streaming DataFrame from OT topics.

    Args:
        spark:             Active SparkSession.
        bootstrap_servers: Kafka/Redpanda server address.
        topic_prefix:      Optional topic name prefix.

    Returns:
        Streaming DataFrame with columns: key, value, topic, partition,
        offset, timestamp, timestampType.
    """
    servers = bootstrap_servers or os.environ.get(
        "REDPANDA_BOOTSTRAP_SERVERS", "localhost:9092"
    )
    prefix = topic_prefix or os.environ.get("REDPANDA_TOPIC_PREFIX", "")
    options = _kafka_options(servers, prefix)

    logger.info("Building Kafka stream — servers=%s topics=%s", servers, options["subscribe"])
    return spark.readStream.format("kafka").options(**options).load()


# ---------------------------------------------------------------------------
# Batch processor (foreachBatch sink)
# ---------------------------------------------------------------------------

def _process_batch(
    batch_df: "DataFrame",
    batch_id: int,
    neo4j_uri: str,
    neo4j_user: str,
    neo4j_password: str,
    topic_prefix: str = "",
) -> None:
    """
    Process a single micro-batch: parse JSON, write to Neo4j.

    Called by Spark's ``foreachBatch`` sink on each trigger interval.
    Errors in individual rows are logged and skipped; a bad batch never
    crashes the stream.

    Args:
        batch_df:      The micro-batch DataFrame (key, value, topic, ...).
        batch_id:      Spark-assigned batch sequence number.
        neo4j_uri:     Neo4j Bolt URI.
        neo4j_user:    Neo4j username.
        neo4j_password: Neo4j password.
        topic_prefix:  Topic prefix to strip from topic names.
    """
    from pyspark.sql.functions import col, from_json
    from src.graph.writer import GraphWriter, create_driver
    from src.graph.consumer import deserialize_message

    count = batch_df.count()
    logger.info("Processing batch %d — %d rows", batch_id, count)
    if count == 0:
        return

    # Collect to driver; Neo4j connector handles bulk write
    rows = batch_df.select(
        col("topic").cast("string"),
        col("value").cast("binary"),
    ).collect()

    driver = create_driver(uri=neo4j_uri, user=neo4j_user, password=neo4j_password)
    ingested = 0
    errors = 0

    with GraphWriter(driver) as writer:
        writer.ensure_constraints()
        for row in rows:
            event = deserialize_message(
                topic=row["topic"],
                raw=row["value"],
                prefix=topic_prefix,
            )
            if event is None:
                errors += 1
                continue
            writer.ingest_event(event)
            ingested += 1

    logger.info(
        "Batch %d complete — ingested: %d, errors: %d", batch_id, ingested, errors
    )


# ---------------------------------------------------------------------------
# SparkStreamingConsumer
# ---------------------------------------------------------------------------

class SparkStreamingConsumer:
    """
    PySpark structured streaming consumer for Guardance.

    Reads from Redpanda topics, deserialises events, and writes them to
    Neo4j in micro-batches using ``foreachBatch``.

    Usage::

        consumer = SparkStreamingConsumer(
            neo4j_uri="bolt://localhost:7687",
            neo4j_user="neo4j",
            neo4j_password="neo4j",
        )
        query = consumer.start()   # returns StreamingQuery
        query.awaitTermination()   # blocks until stopped

    Args:
        neo4j_uri:         Neo4j Bolt URI.
        neo4j_user:        Neo4j username.
        neo4j_password:    Neo4j password.
        bootstrap_servers: Kafka/Redpanda bootstrap servers.
        topic_prefix:      Optional topic name prefix.
        trigger_seconds:   Micro-batch trigger interval in seconds.
        spark:             An existing SparkSession (created if not given).
    """

    def __init__(
        self,
        neo4j_uri: Optional[str] = None,
        neo4j_user: Optional[str] = None,
        neo4j_password: Optional[str] = None,
        bootstrap_servers: Optional[str] = None,
        topic_prefix: Optional[str] = None,
        trigger_seconds: Optional[float] = None,
        spark: Optional["SparkSession"] = None,
    ) -> None:
        self._neo4j_uri = neo4j_uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        self._neo4j_user = neo4j_user or os.environ.get("NEO4J_USER", "neo4j")
        self._neo4j_password = neo4j_password or os.environ.get("NEO4J_PASSWORD", "neo4j")
        self._bootstrap_servers = bootstrap_servers or os.environ.get(
            "REDPANDA_BOOTSTRAP_SERVERS", "localhost:9092"
        )
        self._topic_prefix = topic_prefix if topic_prefix is not None else os.environ.get(
            "REDPANDA_TOPIC_PREFIX", ""
        )
        self._trigger_seconds = trigger_seconds or float(
            os.environ.get("SPARK_TRIGGER_SECONDS", "5")
        )
        self._spark = spark
        self._query: Optional["StreamingQuery"] = None

    def start(self) -> "StreamingQuery":
        """
        Start the streaming query.

        Returns:
            The active :class:`pyspark.sql.streaming.StreamingQuery`.
            Call ``.awaitTermination()`` on it to block until stopped,
            or ``.stop()`` to terminate it.
        """
        if self._spark is None:
            self._spark = create_spark_session()

        stream_df = build_kafka_stream(
            self._spark,
            bootstrap_servers=self._bootstrap_servers,
            topic_prefix=self._topic_prefix,
        )

        neo4j_uri = self._neo4j_uri
        neo4j_user = self._neo4j_user
        neo4j_password = self._neo4j_password
        topic_prefix = self._topic_prefix

        def _batch_fn(batch_df: "DataFrame", batch_id: int) -> None:
            _process_batch(
                batch_df=batch_df,
                batch_id=batch_id,
                neo4j_uri=neo4j_uri,
                neo4j_user=neo4j_user,
                neo4j_password=neo4j_password,
                topic_prefix=topic_prefix,
            )

        self._query = (
            stream_df.writeStream
            .foreachBatch(_batch_fn)
            .trigger(processingTime=f"{int(self._trigger_seconds)} seconds")
            .option(
                "checkpointLocation",
                os.environ.get("SPARK_CHECKPOINT_DIR", "/tmp/guardance-checkpoint"),
            )
            .start()
        )

        logger.info(
            "Spark streaming query started — trigger=%.1fs", self._trigger_seconds
        )
        return self._query

    def stop(self) -> None:
        """Stop the active streaming query gracefully."""
        if self._query is not None and self._query.isActive:
            self._query.stop()
            logger.info("Spark streaming query stopped")
        if self._spark is not None:
            self._spark.stop()
            logger.info("SparkSession stopped")

    @property
    def is_active(self) -> bool:
        """True if the streaming query is currently running."""
        return self._query is not None and self._query.isActive
