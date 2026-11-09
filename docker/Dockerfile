# ═══════════════════════════════════════════════════════════════════════════════
# ServerScrub — local test target
#
# AlmaLinux 8, because that is what the production server runs and the
# differences are not cosmetic. The database corruption incident of 4.35.0 was
# diagnosed on a server whose sqlite is 3.26.0, which has no `.recover` -- the
# first recovery command handed to the operator did not exist on their machine.
# A test environment on a newer sqlite would never have surfaced that.
#
# PHP is a BUILD ARG on purpose. install.sh requires 7.4 or newer, development
# here happens on 8.5, and production runs whatever EA-PHP cPanel installed.
# Testing only the version the developer has is how a release ships syntax the
# floor cannot parse. Shakaal builds both ends of the supported range.
#
#   docker build -t serverscrub-test:php74 --build-arg PHP_STREAM=7.4 docker/
#   docker build -t serverscrub-test:php82 --build-arg PHP_STREAM=8.2 docker/
#
# NOT a cPanel server. There is no cpsrvd, no WHM, no AppConfig and no real
# Exim or ModSecurity here; those surfaces are seeded as files in the shapes
# the product reads (see seed-cpanel.sh). What this catches is everything that
# depends on being Linux: paths, permissions, the Python daemon, the shell
# scripts, inotify, sqlite's real version, and PHP at the supported floor.
# What it cannot catch is cPanel's own API behaviour. Shakaal says which is
# which rather than reporting a pass it has not earned.
# ═══════════════════════════════════════════════════════════════════════════════

FROM almalinux:8

ARG PHP_STREAM=7.4

# `dnf module` is how AlmaLinux 8 offers more than one PHP. The default stream
# is 7.2, which is BELOW the floor install.sh enforces -- so a container built
# without this would fail the install for a reason that has nothing to do with
# the code under test.
RUN dnf -y install dnf-plugins-core epel-release \
 && dnf -y module reset php \
 && dnf -y module enable "php:${PHP_STREAM}" \
 && dnf -y install \
      php-cli php-common php-pdo php-mbstring php-json php-xml php-posix \
      php-pecl-zip \
      sqlite python3 \
      cronie procps-ng findutils tar unzip gzip which diffutils \
      shadow-utils iproute hostname \
      ipset \
 && dnf clean all \
 && rm -rf /var/cache/dnf

# ZipArchive comes from php-pecl-zip on AlmaLinux 8, NOT from php-common.
# Without it tests/test_packaging.php died with `Class "ZipArchive" not found`,
# so the one check that the release artefact is well-formed -- and that tests/
# is absent from it -- never ran in the container at all.
RUN php -r 'exit(class_exists("ZipArchive") ? 0 : 1);' \
 || { echo "FATAL: ZipArchive missing in php:${PHP_STREAM}"; exit 1; }

# ipset is here because install.sh's dependency bootstrap wants it, and the
# layer above ends with `dnf clean all`. So install.sh had to re-download all
# repository metadata to fetch one package, and `up panel` sat on
# "[INFO] Installing: ipset" for minutes before the server ever started.
#
# THE COST, stated rather than hidden: with every dependency already present,
# install.sh takes the "All runtime dependencies already present" branch, so
# the dnf-install branch of the bootstrap is NOT exercised here. That belongs
# in the report's "not tested" list, which is a better trade than a test target
# nobody will wait for.

# php-posix is not in every stream under that name; if it is missing the
# product still runs (it guards every posix_* call), but say so at build time
# rather than discovering it in a test result.
RUN php -m | grep -qi posix || echo "NOTE: posix extension absent in php:${PHP_STREAM}"

# The versions that matter, recorded in the image so a test report can state
# what it actually ran against instead of what it assumed.
RUN { \
      echo "php=$(php -r 'echo PHP_VERSION;')"; \
      echo "sqlite_cli=$(sqlite3 --version | awk '{print $1}')"; \
      echo "sqlite_pdo=$(php -r 'echo (new PDO("sqlite::memory:"))->query("select sqlite_version()")->fetchColumn();')"; \
      echo "python=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"; \
      echo "php_stream=${PHP_STREAM}"; \
    } > /etc/serverscrub-test-env

COPY seed-cpanel.sh /usr/local/bin/seed-cpanel.sh
COPY seed-logs.sh   /usr/local/bin/seed-logs.sh
COPY entrypoint.sh  /usr/local/bin/entrypoint.sh
COPY apachectl-stub.sh /usr/sbin/apachectl
RUN chmod +x /usr/local/bin/seed-cpanel.sh /usr/local/bin/seed-logs.sh              /usr/local/bin/entrypoint.sh /usr/sbin/apachectl  && ln -sf /usr/sbin/apachectl /usr/sbin/apache2ctl

# The install expects to be root on a server. It is root in a container too,
# which is the point: permissions, ownership and the 0700 database directory
# are part of what is being tested.
WORKDIR /opt/serverscrub-src
EXPOSE 8777

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["shell"]
