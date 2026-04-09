#!/bin/bash
FROM=$1 TO=$2 BATCH=$3
echo "Blocks $FROM..$TO, batch $BATCH"
for ((B=FROM; B<=TO; B++)); do
  echo -n "Block $B ... "
  RESP=$(curl -s -X POST http://127.0.0.1:18080/mock/sp1/request \
    -H "x-api-key: test123" \
    -H "Content-Type: application/json" \
    -d '{"block_number": '"$B"', "batch_index": '"$BATCH"'}')
  echo "$RESP"
done