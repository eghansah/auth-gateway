#!/bin/bash

export AUTH_REDIS_SERVER="127.0.0.1:6379"
export AUTH_REDIS_SERVER_DB="15"
export AUTH_SUPPORT_EMAIL="support@support.com"
export AUTH_SESSION_EXPIRY="300s"
export AUTH_HOST="0.0.0.0"
export AUTH_PORT="9000"
export AUTH_URL_PREFIX="/backends"
export AUTH_CSRF_KEY="M2NhZjRhMTNiZjMyY2NjZTBkNzgzNDBm"
export AUTH_DEBUG=TRUE
export AUTH_CORS_ORIGIN_WHITELIST="http://localhost:3000 http://127.0.0.1:3000 http://127.0.0.1:8081 http://localhost:3001"
export AUTH_DBHOST="127.0.0.1"
export AUTH_DBPORT="3306"
export AUTH_DBUSER="admin"
export AUTH_DBPASSWD="password"
export AUTH_DBNAME="auth"
export AUTH_LOGIN_PROVIDER_URL="x"
export AUTH_PROFILE_URL="/backends/auth/profile"
export AUTH_SERVICE_ID="x"
export AUTH_API_KEY="x"
export AUTH_SENDGRID_API_KEY="*" 
export AUTH_LDAP_SERVER_IP="db.debian.org"
export AUTH_LDAP_DOMAIN="local.domain"
export AUTH_SUBDIRECTORY="/"
export FLEXCUBE_DBHOST="x"
export FLEXCUBE_DBPORT=1521
export FLEXCUBE_DBUSERNAME="x"
export FLEXCUBE_DBPASSWORD="x"
export FLEXCUBE_SERVICE_NAME="x"
export MFA_URL="https://"


./build/auth-gateway-server