# pgagroal failover

pgagroal can failover a PostgreSQL instance if the clients can't write to it.

In `pgagroal.conf` define

```
failover = on
failover_script = /path/to/myscript.sh
```

The script will be run as the same user as the pgagroal process so proper
permissions (access and execution) must be in place.

The following information is passed to the script as parameters

1. Old primary host
2. Old primary port
3. New primary host
4. New primary port

so a script could look like

```sh
#!/bin/bash

OLD_PRIMARY_HOST=$1
OLD_PRIMARY_PORT=$2
NEW_PRIMARY_HOST=$3
NEW_PRIMARY_PORT=$4

ssh -tt -o StrictHostKeyChecking=no postgres@${NEW_PRIMARY_HOST} pg_ctl promote -D /mnt/pgdata

if [ $? -ne 0 ]; then
  exit 1
fi

exit 0
```

The script is assumed successful if it has an exit code of 0. Otherwise both servers will be
recorded as failed.
The script is assumed successful if it has an exit code of 0. Otherwise both servers will be recorded as failed.


#### Notifying remaining standbys

After a successful failover, pgagroal can optionally run a notification script to reconfigure standby servers.

**Configuration:**
```sh
failover_notify_script = /path/to/notify_script.sh
```

**Requirements:**
- Requires `failover_script` to be configured
- Runs only after `failover_script` exits with status `0`
- Must be executable by the pgagroal process user

**Script arguments:**

The script receives server information as paired arguments:
```
$1 = old_primary_host
$2 = old_primary_port
$3 = new_primary_host
$4 = new_primary_port
$5 = standby1_host
$6 = standby1_port
$7 = standby2_host
$8 = standby2_port
...
```

If no standbys exist, only the first 4 arguments are passed.

**Example:**
```sh
!/bin/sh

LOGGER_TAG=pgagroal
PGDATA_DIR=/mnt/pgdata 	     # Adjust this to your data directory
REPLICATION_USER=replicator  # Adjust if different

OLD_PRIMARY_HOST=$1
OLD_PRIMARY_PORT=$2
NEW_PRIMARY_HOST=$3
NEW_PRIMARY_PORT=$4
shift 4

logger -s -t $LOGGER_TAG "Failover notification: ${OLD_PRIMARY_HOST}:${OLD_PRIMARY_PORT} -> ${NEW_PRIMARY_HOST}:${NEW_PRIMARY_PORT}"


# Process each standby (host/port pairs)
while [ $# -gt 1 ]; do
    STANDBY_HOST=$1
    STANDBY_PORT=$2
    shift 2
    
    logger -s -t $LOGGER_TAG "Reconfiguring standby ${STANDBY_HOST}:${STANDBY_PORT} to follow new primary..."
    
    # Try pg_rewind first 
    ssh postgres@${STANDBY_HOST} "
        pg_ctl stop -D ${PGDATA_DIR} -m fast &&
        pg_rewind -D ${PGDATA_DIR} --source-server='host=${NEW_PRIMARY_HOST} port=${NEW_PRIMARY_PORT} user=${REPLICATION_USER}' &&
        pg_ctl start -D ${PGDATA_DIR}
    " 2> /tmp/standby_rewind_${STANDBY_HOST}_$$.log
    
    if [ $? -eq 0 ]; then
        logger -s -t $LOGGER_TAG "Standby ${STANDBY_HOST}:${STANDBY_PORT} reconfigured successfully"
        continue
    fi
    
    # Fallback to pg_basebackup if rewind fails
    ssh postgres@${STANDBY_HOST} "
        rm -rf ${PGDATA_DIR}/* &&
        pg_basebackup -h ${NEW_PRIMARY_HOST} -p ${NEW_PRIMARY_PORT} -U ${REPLICATION_USER} -D ${PGDATA_DIR} -Fp -Xs -P -R &&
        pg_ctl start -D ${PGDATA_DIR}
    " 2> /tmp/standby_basebackup_${STANDBY_HOST}_$$.log
    
    if [ $? -ne 0 ]; then
        logger -s -t $LOGGER_TAG "ERROR: Failed to reconfigure standby ${STANDBY_HOST}:${STANDBY_PORT}"
        logger -s -t $LOGGER_TAG < /tmp/standby_basebackup_${STANDBY_HOST}_$$.log
        exit 1
    else
        logger -s -t $LOGGER_TAG "Standby ${STANDBY_HOST}:${STANDBY_PORT} reconfigured successfully"
    fi
done

logger -s -t $LOGGER_TAG "All standbys reconfigured successfully"
exit 0

```
