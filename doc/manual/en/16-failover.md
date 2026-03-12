\newpage

# Failover

[**pgagroal**][pgagroal] can failover a PostgreSQL instance if clients can't write to it.

## Configuration

In `pgagroal.conf` define:

```
failover = on
failover_script = /path/to/myscript.sh
```

The script will be run as the same user as the pgagroal process so proper
permissions (access and execution) must be in place.

## Failover Script

The following information is passed to the script as parameters:

1. Old primary host
2. Old primary port
3. New primary host
4. New primary port

### Example Script

A basic failover script could look like:

```sh
#!/bin/bash

OLD_PRIMARY_HOST=$1
OLD_PRIMARY_PORT=$2
NEW_PRIMARY_HOST=$3
NEW_PRIMARY_PORT=$4

# Promote the new primary
ssh -tt -o StrictHostKeyChecking=no postgres@${NEW_PRIMARY_HOST} pg_ctl promote -D /mnt/pgdata

if [ $? -ne 0 ]; then
  exit 1
fi

exit 0
```

### Script Requirements

- The script is assumed successful if it has an exit code of 0
- Otherwise both servers will be recorded as failed
- The script should handle promotion of the new primary server
- Consider implementing proper error handling and logging

## Advanced Failover Scenarios

### Multiple Replica Configuration

When multiple replicas are available, the failover script can implement logic to:

1. Check replica lag to select the best candidate
2. Ensure proper promotion sequence
3. Update DNS or load balancer configuration
4. Notify monitoring systems

### Automatic Failback

Consider implementing automatic failback when the original primary becomes available:

```sh
#!/bin/bash

# Check if original primary is healthy
if pg_isready -h $OLD_PRIMARY_HOST -p $OLD_PRIMARY_PORT; then
    # Implement failback logic
    echo "Original primary is healthy, considering failback"
fi
```

## Failover Notification Script

After a successful failover, you can optionally configure a notification script to reconfigure standby servers to follow the new primary.

### Configuration

In `pgagroal.conf` add:
```
failover_notify_script = /path/to/notify_script.sh
```

**Important**: The `failover_notify_script` requires `failover_script` to be configured. The notification script runs only after a successful failover.

The script runs with the same permissions as the pgagroal process and must be executable by that user.

### Script Parameters

The notification script receives server information as separate arguments:

1. Old primary host
2. Old primary port
3. New primary host
4. New primary port
5. Standby host (if any)
6. Standby port (if any)
7. Additional standby host/port pairs...

Arguments 5 onwards repeat in pairs (host, port) for each standby server that needs reconfiguration.

### Example Notification Script

A basic notification script to reconfigure standbys:
```sh
#!/bin/sh
#
# This is an example script for pgagroal failover notification.
#
# The script receives information about the old primary, new primary,
# and remaining standby servers that need reconfiguration:
# $1 = old primary hostname
# $2 = old primary port
# $3 = new primary hostname
# $4 = new primary port
# $5 onwards = standby hostname/port pairs
#
# This script reconfigures each standby to follow the new primary by:
# 1. Stopping the standby
# 2. Attempting pg_rewind to sync with new primary
# 3. Falling back to pg_basebackup if pg_rewind fails
# 4. Restarting the standby
#
# Adjust PGDATA_DIR to match your PostgreSQL data directory.
# Ensure the postgres user can SSH without password to standby hosts.
#
# To configure pgagroal:
# failover_notify_script = /path/to/notify_standbys.sh
#

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

### Script Requirements

- The script must exit with code 0 for success
- Non-zero exit codes are logged as errors but don't affect failover completion
- The script should handle cases where no standbys exist (only 4 arguments passed)
- Consider implementing idempotent operations in case the script runs multiple times

### When Notification Runs

The notification script executes only when:

- Failover completes successfully
- `failover_notify_script` is configured
- At least one standby server exists in the configuration

If no standbys need reconfiguration (only primary and new primary exist), the script may still run but receives only the first 4 arguments.


## Monitoring Failover

Monitor failover events through:

- **Log files**: Check pgagroal logs for failover events
- **Prometheus metrics**: Monitor server status changes
- **External monitoring**: Implement alerts for failover events

## Best Practices

1. **Test failover scripts** regularly in non-production environments
2. **Monitor replica lag** to ensure replicas are suitable for promotion
3. **Implement proper logging** in failover scripts for troubleshooting
4. **Consider network partitions** and split-brain scenarios
5. **Document failover procedures** for operational teams
6. **Use configuration management** to ensure consistent failover scripts across environments