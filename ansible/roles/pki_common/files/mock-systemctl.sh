#!/bin/bash
# Mock systemctl for container environments
# Provides minimal compatibility for pkispawn

# Parse arguments - skip flags (--quiet, etc.)
QUIET=false
CMD=""
SERVICE=""
for arg in "$@"; do
    case "$arg" in
        --quiet|-q)
            QUIET=true
            ;;
        --*)
            # Skip other flags
            ;;
        *)
            if [ -z "$CMD" ]; then
                CMD="$arg"
            elif [ -z "$SERVICE" ]; then
                SERVICE="$arg"
            fi
            ;;
    esac
done

# Extract instance name from service (e.g., pki-tomcatd@pki-ecc-root-ca.service -> pki-ecc-root-ca)
INSTANCE="${SERVICE%.service}"
INSTANCE="${INSTANCE#*@}"

log_msg() {
    if [ "$QUIET" != "true" ]; then
        echo "mock-systemctl: $*"
    fi
}

case "$CMD" in
    daemon-reload)
        log_msg "daemon-reload (no-op)"
        exit 0
        ;;
    enable|disable)
        log_msg "$CMD $SERVICE (no-op)"
        exit 0
        ;;
    start)
        log_msg "starting $INSTANCE"
        if [[ "$INSTANCE" == pki-* ]]; then
            export CATALINA_BASE="/var/lib/pki/$INSTANCE"
            export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/jre-17-openjdk}"

            # Check if already running
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    log_msg "Tomcat already running (PID $PID)"
                    exit 0
                fi
            fi

            log_msg "Starting Tomcat for $INSTANCE..."

            # Try multiple methods to start Tomcat
            if [ -x /usr/share/pki/server/bin/pkidaemon ]; then
                log_msg "Using pkidaemon..."
                /usr/share/pki/server/bin/pkidaemon start "$INSTANCE" 2>&1 | while read line; do log_msg "$line"; done
            elif command -v pki-server &>/dev/null; then
                log_msg "Using pki-server..."
                nohup pki-server run "$INSTANCE" > /var/log/pki/$INSTANCE/catalina.out 2>&1 &
                echo $! > "$CATALINA_BASE/conf/tomcat.pid"
            else
                log_msg "Using direct Java invocation..."
                CLASSPATH="/usr/share/tomcat/lib/*:/usr/share/pki/server/lib/*"
                nohup java -Dcatalina.base="$CATALINA_BASE" \
                    -Dcatalina.home="/usr/share/tomcat" \
                    -Djava.io.tmpdir="$CATALINA_BASE/temp" \
                    -classpath "$CLASSPATH" \
                    org.apache.catalina.startup.Bootstrap start \
                    > /var/log/pki/$INSTANCE/catalina.out 2>&1 &
                echo $! > "$CATALINA_BASE/conf/tomcat.pid"
            fi

            sleep 3
        fi
        exit 0
        ;;
    stop)
        log_msg "stopping $INSTANCE"
        if [[ "$INSTANCE" == pki-* ]]; then
            export CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                /usr/share/tomcat/bin/shutdown.sh 2>/dev/null || true
            fi
        fi
        exit 0
        ;;
    restart|reload)
        log_msg "$CMD $INSTANCE"
        $0 stop "$SERVICE"
        sleep 2
        $0 start "$SERVICE"
        exit 0
        ;;
    status)
        log_msg "status $INSTANCE"
        if [[ "$INSTANCE" == pki-* ]]; then
            CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    echo "active"
                    exit 0
                fi
            fi
        fi
        echo "inactive"
        exit 3
        ;;
    is-active)
        if [[ "$INSTANCE" == pki-* ]]; then
            CATALINA_BASE="/var/lib/pki/$INSTANCE"
            if [ -f "$CATALINA_BASE/conf/tomcat.pid" ]; then
                PID=$(cat "$CATALINA_BASE/conf/tomcat.pid" 2>/dev/null)
                if kill -0 "$PID" 2>/dev/null; then
                    [ "$QUIET" != "true" ] && echo "active"
                    exit 0
                fi
            fi
        fi
        [ "$QUIET" != "true" ] && echo "inactive"
        exit 3
        ;;
    is-enabled)
        echo "enabled"
        exit 0
        ;;
    show)
        exit 0
        ;;
    *)
        log_msg "unknown command '$CMD' (no-op)"
        exit 0
        ;;
esac
