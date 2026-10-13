#!/usr/bin/env bash
set -euo pipefail

SCENARIO="${SCENARIO:-S01a}"
ENV_FILE="/scenarios/${SCENARIO}.env"

echo "[*] Mailserver starting for scenario: ${SCENARIO}"

if [ -f "${ENV_FILE}" ]; then
  echo "[*] Loading scenario environment from ${ENV_FILE}"
  # Export variables from env file
  set -a
  # shellcheck source=/dev/null
  . "${ENV_FILE}"
  set +a
fi

# Ensure user labuser exists with planted password
if ! id "labuser" &>/dev/null; then
  useradd -m -s /bin/bash labuser
  echo "labuser:LabPass-123!" | chpasswd
  echo "labuser" | saslpasswd2 -p -c -u lab.local labuser || true
fi

# Configure Postfix base settings
postconf -e "myhostname = mailserver.lab.local"
postconf -e "mydomain = lab.local"
postconf -e "myorigin = \$mydomain"
postconf -e "inet_interfaces = all"
postconf -e "inet_protocols = ipv4"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain"
postconf -e "mynetworks = 127.0.0.0/8, 172.28.0.0/24"
postconf -e "smtputf8_enable = no"

# Apply scenario-specific TLS settings
postconf -e "smtpd_tls_security_level = ${smtpd_tls_security_level:-may}"
postconf -e "smtpd_tls_protocols = ${smtpd_tls_protocols:-!SSLv2,!SSLv3,!TLSv1,!TLSv1.1}"
postconf -e "smtpd_tls_ciphers = ${smtpd_tls_ciphers:-high}"
postconf -e "smtpd_tls_mandatory_ciphers = ${smtpd_tls_mandatory_ciphers:-high}"

if [ -n "${smtpd_tls_cert_file:-}" ] && [ -f "${smtpd_tls_cert_file}" ]; then
  postconf -e "smtpd_tls_cert_file = ${smtpd_tls_cert_file}"
fi

if [ -n "${smtpd_tls_key_file:-}" ] && [ -f "${smtpd_tls_key_file}" ]; then
  postconf -e "smtpd_tls_key_file = ${smtpd_tls_key_file}"
fi

# SASL auth settings
postconf -e "smtpd_sasl_auth_enable = ${smtpd_sasl_auth_enable:-no}"
postconf -e "smtpd_tls_auth_only = ${smtpd_tls_auth_only:-no}"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"

echo "[*] Postfix configuration applied:"
postconf -n | grep smtpd_tls || true

# Start services
service postfix start

# Keep container running and tail logs
tail -F /var/log/mail.log 2>/dev/null || tail -f /dev/null
