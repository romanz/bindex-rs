-- Show cached history per transaction

WITH
    per_tx AS (
        SELECT 
            block_height, 
            block_offset, 
            sum(amount) AS delta
        FROM history GROUP BY 1, 2
    ),
    totals AS (
        SELECT 
            block_height, 
            block_offset, 
            sum(delta) OVER (
                ORDER BY block_height DESC, block_offset DESC 
                ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING
            ) AS total
        FROM per_tx
    )

SELECT 
    format("%dx%d", block_height, block_offset) AS `tx`, 
    total/1e5 AS `[mBTC]`
FROM totals
