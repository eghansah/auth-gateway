FROM golang:1.21 AS builder

WORKDIR /usr/src/app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go build -o auth-gateway ./cmd/auth-gateway-server


FROM ubuntu  
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/auth-gateway ./
ADD ./cmd/auth-gateway-server/html/ html/
ADD ./cmd/auth-gateway-server/templates/ templates/

ENV AUTH_REDIS_SERVER=127.0.0.1:6379
ENV AUTH_REDIS_SERVER_DB=15
ENV AUTH_SUPPORT_EMAIL=support@support.com
ENV AUTH_SESSION_EXPIRY=300s
ENV AUTH_HOST=0.0.0.0
ENV AUTH_PORT=9000
ENV AUTH_URL_PREFIX=/backends
ENV AUTH_CSRF_KEY=M2NhZjRhMTNiZjMyY2NjZTBkNzgzNDBm
ENV AUTH_DEBUG=TRUE
ENV AUTH_CORS_ORIGIN_WHITELIST="http://localhost:3000 http://127.0.0.1:3000 http://127.0.0.1:8081 http://localhost:3001"
ENV AUTH_DBHOST=127.0.0.1
ENV AUTH_DBPORT=3306
ENV AUTH_DBUSER=admin
ENV AUTH_DBPASSWD=password
ENV AUTH_DBNAME=auth
ENV AUTH_LOGIN_PROVIDER_URL=x
ENV AUTH_PROFILE_URL=/backends/auth/profile
ENV AUTH_SERVICE_ID=x
ENV AUTH_API_KEY=x
ENV AUTH_SENDGRID_API_KEY=* 
ENV AUTH_LDAP_SERVER_IP=db.debian.org
ENV AUTH_LDAP_DOMAIN=local.domain
ENV AUTH_SUBDIRECTORY=/
ENV MFA_URL=https://
ENV AUTH_DB_TYPE=mssql

EXPOSE 80

CMD ["/usr/src/app/auth-gateway"]
