#!/bin/bash
# Build the Pathrunner Kinesis Analytics payload JAR.
# Requires Docker (no local Java/Maven installation needed).
# Output: jars/payload.jar (embedded into the pathrunner binary via go:embed)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="$SCRIPT_DIR/payload.jar"

echo "Building Kinesis Analytics payload JAR..."
echo "Source: $SCRIPT_DIR/src"

docker run --rm \
    -v "$SCRIPT_DIR":/build \
    -w /build \
    maven:3.9-eclipse-temurin-11 \
    mvn package -q --no-transfer-progress

# The shaded JAR is the one without 'original-' prefix
BUILT_JAR=$(find "$SCRIPT_DIR/target" -name "pathrunner-kinesisanalytics-payload-*.jar" ! -name "original-*" | head -1)

if [ -z "$BUILT_JAR" ]; then
    echo "ERROR: Could not find built JAR in target/"
    exit 1
fi

cp "$BUILT_JAR" "$OUTPUT"
echo "Done: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
