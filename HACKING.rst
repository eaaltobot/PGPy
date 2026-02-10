Releases
------------

Rebuild previous

```
export SOURCE_DATE_EPOCH=$(cat source_date_epoch)
python3 -m build --wheel
```

New release

```
export SOURCE_DATE_EPOCH=$(date +%s)
echo "${SOURCE_DATE_EPOCH}" > source_date_epoch
python3 -m build --wheel
```
