"""
Spark window aggregations for the Guardance Behavioral Baseline Engine.

Two window strategies are implemented:

    Tumbling (5-minute):
        Non-overlapping fixed-size windows.  Each window contains all
        events in its [start, end) interval.  Used for computing per-device
        packet rate baselines.

    Sliding (30-minute, 5-minute slide):
        Overlapping windows that advance every 5 minutes.  Events at the
        window boundary belong to multiple windows.  Used for anomaly
        detection where sustained deviations matter more than spikes.

The Spark code is imported lazily so the module loads cleanly when PySpark
is not installed (tests mock the import).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Window parameters (seconds)
TUMBLING_WINDOW_S = 5 * 60      # 5 minutes
SLIDING_WINDOW_S  = 30 * 60     # 30 minutes
SLIDING_STEP_S    = 5 * 60      # 5-minute slide


def build_tumbling_window(df: Any, timestamp_col: str = "ts") -> Any:
    """
    Apply a 5-minute tumbling window aggregation to a Spark DataFrame.

    Groups by device IP and tumbling window, aggregating:
        - packet_count (sum)
        - avg_interval_ms (mean)
        - protocol_count (count distinct protocols)

    Args:
        df:            A Spark DataFrame with columns: ip, ts, protocol,
                       packet_count, avg_interval_ms.
        timestamp_col: Name of the timestamp column (epoch seconds as
                       LongType or TimestampType).

    Returns:
        Aggregated Spark DataFrame.
    """
    try:
        from pyspark.sql import functions as F
        from pyspark.sql.functions import col, window

        windowed = (
            df.groupBy(
                col("ip"),
                window(col(timestamp_col).cast("timestamp"), f"{TUMBLING_WINDOW_S} seconds"),
            )
            .agg(
                F.sum("packet_count").alias("total_packets"),
                F.avg("avg_interval_ms").alias("mean_interval_ms"),
                F.countDistinct("protocol").alias("protocol_count"),
            )
            .select(
                col("ip"),
                col("window.start").alias("window_start"),
                col("window.end").alias("window_end"),
                col("total_packets"),
                col("mean_interval_ms"),
                col("protocol_count"),
            )
        )
        logger.debug("Built 5-min tumbling window aggregation")
        return windowed
    except ImportError:
        logger.warning("PySpark not available — tumbling window skipped")
        return None


def build_sliding_window(df: Any, timestamp_col: str = "ts") -> Any:
    """
    Apply a 30-minute sliding window (5-minute slide) to a Spark DataFrame.

    Each output row covers a 30-minute period and is updated every 5 minutes.
    Aggregates:
        - packet_count (sum)
        - avg_interval_ms (mean and std dev)
        - anomaly_candidate (flag: std/mean > 0.2 suggests deviation)

    Args:
        df:            A Spark DataFrame with columns: ip, ts, protocol,
                       packet_count, avg_interval_ms.
        timestamp_col: Name of the timestamp column.

    Returns:
        Aggregated Spark DataFrame.
    """
    try:
        from pyspark.sql import functions as F
        from pyspark.sql.functions import col, window

        windowed = (
            df.groupBy(
                col("ip"),
                window(
                    col(timestamp_col).cast("timestamp"),
                    f"{SLIDING_WINDOW_S} seconds",
                    f"{SLIDING_STEP_S} seconds",
                ),
            )
            .agg(
                F.sum("packet_count").alias("total_packets"),
                F.avg("avg_interval_ms").alias("mean_interval_ms"),
                F.stddev("avg_interval_ms").alias("std_interval_ms"),
            )
            .withColumn(
                "anomaly_candidate",
                (
                    (col("std_interval_ms").isNotNull())
                    & (col("mean_interval_ms") > 0)
                    & ((col("std_interval_ms") / col("mean_interval_ms")) > 0.2)
                ),
            )
            .select(
                col("ip"),
                col("window.start").alias("window_start"),
                col("window.end").alias("window_end"),
                col("total_packets"),
                col("mean_interval_ms"),
                col("std_interval_ms"),
                col("anomaly_candidate"),
            )
        )
        logger.debug("Built 30-min sliding window aggregation")
        return windowed
    except ImportError:
        logger.warning("PySpark not available — sliding window skipped")
        return None


def build_streaming_baseline_query(spark: Any, kafka_servers: str, topic: str) -> Any:
    """
    Build a Spark Structured Streaming query that maintains rolling baseline
    statistics and writes anomalous windows to the console (or a sink).

    Combines the tumbling window (rate baseline) with the sliding window
    (deviation detection) via a foreachBatch sink that updates the
    :class:`~src.baseline.engine.BaselineEngine` store.

    Args:
        spark:         SparkSession.
        kafka_servers: Comma-separated Kafka bootstrap server addresses.
        topic:         Kafka topic to consume (e.g. ``"raw.modbus"``).

    Returns:
        A Spark StreamingQuery, or None if PySpark is unavailable.
    """
    try:
        from pyspark.sql import functions as F
        from pyspark.sql.types import (
            DoubleType,
            LongType,
            StringType,
            StructField,
            StructType,
        )

        _schema = StructType([
            StructField("ip",              StringType(), True),
            StructField("ts",              LongType(),   True),
            StructField("protocol",        StringType(), True),
            StructField("packet_count",    LongType(),   True),
            StructField("avg_interval_ms", DoubleType(), True),
        ])

        raw = (
            spark.readStream
            .format("kafka")
            .option("kafka.bootstrap.servers", kafka_servers)
            .option("subscribe", topic)
            .option("startingOffsets", "latest")
            .load()
        )

        parsed = raw.select(
            F.from_json(
                F.col("value").cast("string"), _schema
            ).alias("data")
        ).select("data.*")

        windowed = build_sliding_window(parsed)
        if windowed is None:
            return None

        query = (
            windowed.writeStream
            .outputMode("update")
            .format("console")
            .option("truncate", False)
            .trigger(processingTime=f"{SLIDING_STEP_S} seconds")
            .start()
        )
        logger.info("Started Spark baseline streaming query on topic %s", topic)
        return query

    except ImportError:
        logger.warning("PySpark not available — streaming baseline query skipped")
        return None
