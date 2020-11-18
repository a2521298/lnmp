#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# Check if user is root
if [ $(id -u) != "0" ]; then
    echo "Error: You must be root to run this script, please use root to install lcmp"
    exit 1
fi

clear
echo "========================================================================="
echo "lcmp V0.9 for CentOS/RadHat Linux VPS  Written by Licess Modify by PONPONPON"
echo "========================================================================="
echo "A tool to auto-compile & install Cherokee+MySQL+PHP on Linux "
echo "========================================================================="
cur_dir=$(pwd)

if [ "$1" != "--help" ]; then

#set mysql root password

	echo "==========================="
	mysqlrootpwd="ercpzE9L3LoMQpkgUsDH4KIG10e5pMmK"
	echo "Please input the root password of mysql:"
	read -p "(Default password: root):" mysqlrootpwd
	if [ "$mysqlrootpwd" = "" ]; then
		mysqlrootpwd="ercpzE9L3LoMQpkgUsDH4KIG10e5pMmK"
	fi
	echo "==========================="
	echo "mysqlrootpwd=$mysqlrootpwd"
	echo "==========================="

	get_char()
	{
	SAVEDSTTY=`stty -g`
	stty -echo
	stty cbreak
	dd if=/dev/tty bs=1 count=1 2> /dev/null
	stty -raw
	stty echo
	stty $SAVEDSTTY
	}
	echo ""
	echo "Press any key to start..."
	char=`get_char`


echo "============================system setting================================="
Centos8Check=$(cat /etc/redhat-release | grep ' 8.' | grep -iE 'centos|Red Hat')

#Set timezone
rm -rf /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
yum install -y ntp
ntpdate -u pool.ntp.org
date

rpm -qa|grep httpd
rpm -e httpd httpd-tools --nodeps
rpm -qa|grep mysql
rpm -e mysql mysql-libs --nodeps
rpm -qa|grep mariadb
rpm -e mariadb mariadb-libs --nodeps
rpm -qa|grep php
rpm -e php-mysql php-cli php-gd php-common php --nodeps

yum -y remove httpd*
yum -y remove mysql-server mysql mysql-libs mariadb-server mariadb mariadb-libs
yum -y remove php*
yum clean all
#yum -y update

#Disable SeLinux
setenforce 0
if [ -s /etc/selinux/config ]; then
sed -i 's/^SELINUX=.*$/SELINUX=disabled/' /etc/selinux/config
fi

    if grep -Eqi '^127.0.0.1[[:space:]]*localhost' /etc/hosts; then
        echo "Hosts: ok."
    else
        echo "127.0.0.1 localhost.localdomain localhost" >> /etc/hosts
    fi
    pingresult=`ping -c1 www.cloudflare.com 2>&1`
    echo "${pingresult}"
    if echo "${pingresult}" | grep -q "unknown host"; then
        echo "DNS...fail"
        echo "Writing nameserver to /etc/resolv.conf ..."
        echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
    else
        echo "DNS...ok"
    fi
	
    if [ -s /etc/yum.conf ]; then
        \cp /etc/yum.conf /etc/yum.conf.lnmp
        sed -i 's:exclude=.*:exclude=:g' /etc/yum.conf
    fi
	
	if [ "${Centos8Check}" ];then
		yum config-manager --set-enabled PowerTools
	fi

for packages in make cmake3 gcc gcc-c++ gcc-g77 flex bison file libtool libtool-libs autoconf kernel-devel patch wget libjpeg libjpeg-devel libpng libpng-devel libpng10 libpng10-devel gd gd-devel libxml2 libxml2-devel zlib zlib-devel glib2 glib2-devel tar bzip2 bzip2-devel libevent libevent-devel ncurses ncurses-devel curl curl-devel libcurl libcurl-devel e2fsprogs e2fsprogs-devel krb5 krb5-devel libidn libidn-devel openssl openssl-devel vim-minimal gettext gettext-devel gmp-devel pspell-devel libcap diffutils ca-certificates net-tools libc-client-devel psmisc libXpm-devel c-ares-devel libicu-devel libxslt libxslt-devel zip unzip glibc.i686 libstdc++.so.6 cairo-devel bison-devel libaio-devel perl perl-devel perl-Data-Dumper lsof pcre pcre-devel vixie-cron crontabs expat-devel readline-devel oniguruma-devel libwebp-devel libvpx-devel git traceoute sqlite-devel;
do yum -y install $packages; done

mv -f /etc/yum.conf.ltmp /etc/yum.conf
yum -y update bash openssl glibc cmake3
ln -sf /usr/bin/cmake3 /usr/bin/cmake

function is_64bit(){
    if [ `getconf WORD_BIT` = '32' ] && [ `getconf LONG_BIT` = '64' ] ; then
        return 0
    else
        return 1
    fi        
}

	SYS_VERSION=$(cat /etc/redhat-release)
	SYS_INFO=$(uname -msr)
	SYS_BIT=$(getconf LONG_BIT)
	MEM_TOTAL=$(free -m|grep Mem|awk '{print $2}')
	CPU_INFO=$(getconf _NPROCESSORS_ONLN)
	GCC_VER=$(gcc -v 2>&1|grep "gcc version"|awk '{print $3}')
	CMAKE_VER=$(cmake --version|grep version|awk '{print $3}')

	echo -e ${SYS_VERSION}
	echo -e Bit:${SYS_BIT} Mem:${MEM_TOTAL}M Core:${CPU_INFO} gcc:${GCC_VER} cmake:${CMAKE_VER}
	echo -e ${SYS_INFO}

cpuInfo=$(getconf _NPROCESSORS_ONLN)
if [ "${cpuInfo}" -ge "4" ];then
	GetCpuStat
else
	cpuCore="1"
fi

GetCpuStat(){
	time1=$(cat /proc/stat |grep 'cpu ')
	sleep 1
	time2=$(cat /proc/stat |grep 'cpu ')
	cpuTime1=$(echo ${time1}|awk '{print $2+$3+$4+$5+$6+$7+$8}')
	cpuTime2=$(echo ${time2}|awk '{print $2+$3+$4+$5+$6+$7+$8}')
	runTime=$((${cpuTime2}-${cpuTime1}))
	idelTime1=$(echo ${time1}|awk '{print $5}')
	idelTime2=$(echo ${time2}|awk '{print $5}')
	idelTime=$((${idelTime2}-${idelTime1}))
	useTime=$(((${runTime}-${idelTime})*3))
	[ ${useTime} -gt ${runTime} ] && cpuBusy="true"
	if [ "${cpuBusy}" == "true" ]; then
		cpuCore=$((${cpuInfo}/2))
	else
		cpuCore=$((${cpuInfo}-1))
	fi
}

echo -e ${cpuCore}
sleep 10
#GetCpuStat
echo "============================system setting completed================================="

echo "============================check memory=================================="
Mem=`free -m | awk '/Mem:/{print $2}'`
Swap=`free -m | awk '/Swap:/{print $2}'`

if [ "$Swap" == '0' ] ;then
    if [ $Mem -le 1024 ];then
    COUNT=2048
    dd if=/dev/zero of=/swapfile count=$COUNT bs=1M
    mkswap /swapfile
    swapon /swapfile
    chmod 600 /swapfile
#[ -z "`grep swapfile /etc/fstab`" ] && cat >> /etc/fstab << EOF
#/swapfile    swap    swap    defaults    0 0
#EOF
    elif [ $Mem -gt 1024 -a $Mem -le 2048 ];then
    COUNT=2048
    dd if=/dev/zero of=/swapfile count=$COUNT bs=1M
    mkswap /swapfile
    swapon /swapfile
    chmod 600 /swapfile
#[ -z "`grep swapfile /etc/fstab`" ] && cat >> /etc/fstab << EOF
#/swapfile    swap    swap    defaults    0 0
#EOF
    fi
fi
echo "============================check memory completed=================================="

echo "============================check files=================================="
if [ -s php-7.4.11.tar.gz ]; then
  echo "php-7.4.11.tar.gz [found]"
  else
  echo "Error: php-7.4.11.tar.gz not found!!!download now......"
  wget -c http://cn2.php.net/distributions/php-7.4.11.tar.gz
fi

if [ -s php-7.0.33.tar.gz ]; then
  echo "php-7.0.33.tar.gz [found]"
  else
  echo "Error: php-7.0.33.tar.gz not found!!!download now......"
  wget -c http://cn2.php.net/distributions/php-7.0.33.tar.gz
fi

if [ -s redis-5.0.10.tar.gz ]; then
  echo "redis-5.0.10.tar.gz [found]"
  else
  echo "Error: redis-5.0.10.tar.gz not found!!!download now......"
  wget -c https://download.redis.io/releases/redis-5.0.10.tar.gz
fi

if [ -s pcre-8.44.tar.gz ]; then
  echo "pcre-8.44.tar.gz [found]"
  else
  echo "Error: pcre-8.44.tar.gz not found!!!download now......"
  wget -c https://ftp.pcre.org/pub/pcre/pcre-8.44.tar.gz
fi

if [ -s openlitespeed-1.6.17.tgz ]; then
  echo "openlitespeed-1.6.17.tgz [found]"
  else
  echo "Error: openlitespeed-1.6.17.tgz not found!!!download now......"
  wget -c https://openlitespeed.org/packages/openlitespeed-1.6.17.src.tgz
fi

if [ -s nginx-1.18.0.tar.gz ]; then
  echo "nginx-1.18.0.tar.gz [found]"
  else
  echo "Error: nginx-1.18.0.tar.gz not found!!!download now......"
  wget -c http://nginx.org/download/nginx-1.18.0.tar.gz
fi

if [ -s mariadb-10.5.8.tar.gz ]; then
  echo "mariadb-10.5.8.tar.gz [found]"
  else
  echo "Error: mariadb-10.5.8.tar.gz not found!!!download now......"
  wget -c https://downloads.mariadb.com/MariaDB/mariadb-10.5.8/source/mariadb-10.5.8.tar.gz
fi

if [ -s libiconv-1.16.tar.gz ]; then
  echo "libiconv-1.16.tar.gz [found]"
  else
  echo "Error: libiconv-1.16.tar.gz not found!!!download now......"
  wget -c http://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.16.tar.gz
fi

if [ -s libmcrypt-2.5.8.tar.gz ]; then
  echo "libmcrypt-2.5.8.tar.gz [found]"
  else
  echo "Error: libmcrypt-2.5.8.tar.gz not found!!!download now......"
  wget -c http://downloads.sourceforge.net/mcrypt/libmcrypt-2.5.8.tar.gz
fi

if [ -s mhash-0.9.9.9.tar.gz ]; then
  echo "mhash-0.9.9.9.tar.gz [found]"
  else
  echo "Error: mhash-0.9.9.9.tar.gz not found!!!download now......"
  wget -c http://downloads.sourceforge.net/mhash/mhash-0.9.9.9.tar.gz
fi

if [ -s mcrypt-2.6.8.tar.gz ]; then
  echo "mcrypt-2.6.8.tar.gz [found]"
  else
  echo "Error: mcrypt-2.6.8.tar.gz not found!!!download now......"
  wget -c http://downloads.sourceforge.net/mcrypt/mcrypt-2.6.8.tar.gz
fi

if [ -s phpMyAdmin-4.9.7-all-languages.tar.gz ]; then
  echo "phpMyAdmin-4.9.7-all-languages.tar.gz [found]"
  else
  echo "Error: phpMyAdmin-4.9.7-all-languages.tar.gz not found!!!download now......"
  wget -c https://files.phpmyadmin.net/phpMyAdmin/4.9.7/phpMyAdmin-4.9.7-all-languages.tar.gz
fi

#if [ -s libevent-2.1.8-stable.tar.gz ]; then
#  echo "libevent-2.1.8-stable.tar.gz [found]"
#  else
#  echo "Error: libevent-2.1.8-stable.tar.gz not found!!!download now......"
#  wget -c https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
#fi

if [ -s memcached-1.6.8.tar.gz ]; then
  echo "memcached-1.6.8.tar.gz [found]"
  else
  echo "Error: memcached-1.6.8.tar.gz not found!!!download now......"
  wget -c http://www.memcached.org/files/memcached-1.6.8.tar.gz
fi

#if [ -s autoconf-2.69.tar.gz ]; then
#  echo "autoconf-2.69.tar.gz [found]"
#  else
#  echo "Error: autoconf-2.69.tar.gz not found!!!download now......"
#  wget -c http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
#fi

if [ -s jemalloc-5.2.1.tar.bz2 ]; then
  echo "jemalloc-5.2.1.tar.bz2 [found]"
  else
  echo "Error: jemalloc-5.2.1.tar.bz2 not found!!!download now......"
  wget -c https://github.com/jemalloc/jemalloc/releases/download/5.2.1/jemalloc-5.2.1.tar.bz2
fi

if [ -s openssl-1.1.1h.tar.gz ]; then
  echo "openssl-1.1.1h.tar.gz [found]"
  else
  echo "Error: openssl-1.1.1h.tar.gz not found!!!download now......"
  wget -c https://www.openssl.org/source/openssl-1.1.1h.tar.gz
fi
echo "============================check files completed=================================="

lib(){
echo "============================files install================================="
#cd $cur_dir
#tar zxvf autoconf-2.69.tar.gz
#cd autoconf-2.69/
#./configure
#make -j2 && make install
#cd ../

cd $cur_dir
tar zxvf libiconv-1.16.tar.gz
cd libiconv-1.16/
./configure --enable-static
make -j2 && make install
cd ../

cd $cur_dir
tar zxvf libmcrypt-2.5.8.tar.gz
cd libmcrypt-2.5.8/
./configure
make -j2 && make install
/sbin/ldconfig
cd libltdl/
./configure --enable-ltdl-install
make -j2 && make install
    ln -sf /usr/local/lib/libmcrypt.la /usr/lib/libmcrypt.la
    ln -sf /usr/local/lib/libmcrypt.so /usr/lib/libmcrypt.so
    ln -sf /usr/local/lib/libmcrypt.so.4 /usr/lib/libmcrypt.so.4
    ln -sf /usr/local/lib/libmcrypt.so.4.4.8 /usr/lib/libmcrypt.so.4.4.8
    ldconfig
cd ../../

cd $cur_dir
tar zxvf mhash-0.9.9.9.tar.gz
cd mhash-0.9.9.9/
./configure
make -j2 && make install
    ln -sf /usr/local/lib/libmhash.a /usr/lib/libmhash.a
    ln -sf /usr/local/lib/libmhash.la /usr/lib/libmhash.la
    ln -sf /usr/local/lib/libmhash.so /usr/lib/libmhash.so
    ln -sf /usr/local/lib/libmhash.so.2 /usr/lib/libmhash.so.2
    ln -sf /usr/local/lib/libmhash.so.2.0.1 /usr/lib/libmhash.so.2.0.1
    ldconfig
cd ../

cd $cur_dir
tar zxvf mcrypt-2.6.8.tar.gz
cd mcrypt-2.6.8/
./configure
make -j2 && make install
#make && make install
cd ../

cd $cur_dir
tar xjf jemalloc-5.2.1.tar.bz2
cd jemalloc-5.2.1/
./configure
make -j2 && make install
	#if is_64bit; then
	#ln -s /usr/local/lib/libjemalloc.so.2 /usr/lib64/libjemalloc.so.2
	#else
	#ln -s /usr/local/lib/libjemalloc.so.2 /usr/lib/libjemalloc.so.2
	#fi
	ln -s /usr/local/lib/libjemalloc.so.2 /usr/lib/libjemalloc.so.2
echo '/usr/local/lib' > /etc/ld.so.conf.d/local.conf
ldconfig
cd ../

cd $cur_dir
tar zxvf openssl-1.1.1h.tar.gz
mv openssl-1.1.1h openssl
tar zxvf openssl-1.1.1h.tar.gz
cd openssl-1.1.1h/
./config -fPIC --prefix=/usr/local/openssl --openssldir=/usr/local/openssl zlib-dynamic shared
make -j2 && make install
cd ../
#mv /usr/bin/openssl /usr/bin/openssl.old
#mv /usr/lib64/openssl/engines /usr/lib64/openssl/engines.old
#mv /usr/include/openssl /usr/include/openssl.old
#ln -s /usr/local/openssl/bin/openssl /usr/bin/openssl
#ln -s /usr/local/openssl/lib/engines-1.1 /usr/lib64/openssl/engines
#ln -s /usr/local/openssl/include/openssl /usr/include/openssl
#ln -s /usr/local/openssl/lib/libcrypto.so.1.1 /usr/lib/
#ln -s /usr/local/openssl/lib/libssl.so.1.1 /usr/lib/
#echo "/usr/local/openssl/lib" >> /etc/ld.so.conf.d/openssl.conf
#ldconfig
#openssl version

# /etc/security/limits.conf
[ -e /etc/security/limits.d/*nproc.conf ] && rename nproc.conf nproc.conf_bak /etc/security/limits.d/*nproc.conf
#sed -i 's@#DefaultLimitCORE=@DefaultLimitCORE=infinity@g' /etc/systemd/system.conf
sed -i 's@#DefaultLimitNOFILE=@DefaultLimitNOFILE=65535@g' /etc/systemd/system.conf
sed -i 's@#DefaultLimitNPROC=@DefaultLimitNPROC=65535@g' /etc/systemd/system.conf
sed -i '/^# End of file/,$d' /etc/security/limits.conf
cat >> /etc/security/limits.conf <<EOF
# End of file
* soft nproc 65535
* hard nproc 65535
* soft nofile 65535
* hard nofile 65535
EOF
[ -z "`grep 'ulimit -SH 65535' /etc/rc.local`" ] && echo "ulimit -SH 65535" >> /etc/rc.local
echo "============================files install completed================================="
}
lib

echo "============================phpMyAdmin+menu install================================="
#add user
groupadd www
useradd -s /sbin/nologin -M -g www www
groupadd mysql
useradd -s /sbin/nologin -M -g mysql mysql
groupadd memcached
useradd -s /sbin/nologin -M -g memcached memcached
groupadd mysql
useradd -s /sbin/nologin -M -g redis redis
mkdir -p /www/wwwroot
mkdir -p /www/wwwlogs
mkdir -p /www/wwwhost
mkdir -p /www/wwwcert

#phpmyadmin
cd $cur_dir
tar zxvf phpMyAdmin-4.9.7-all-languages.tar.gz
mv phpMyAdmin-4.9.7-all-languages /www/wwwroot/phpmyadmin/
chown -R www:www /www/wwwroot
echo "============================phpMyAdmin+menu install completed================================="

echo "============================web+pcre install================================="
cd $cur_dir
tar zxvf pcre-8.44.tar.gz
mv pcre-8.44 pcre
tar zxvf pcre-8.44.tar.gz
cd pcre-8.44/
./configure
make -j2 && make install
cd ../

ldconfig
cd $cur_dir
#tar zxvf openlitespeed-1.6.17.tgz
cd openlitespeed-1.6.17/
./configure --prefix=/usr/local/lsws --with-user=www --with-group=www --enable-adminssl=yes
make -j2 && make install
cd ../
chown -R lsadm:lsadm /usr/local/lsws/conf
sed -i 's@//fonts.googleapis.com@http://fonts.useso.com@' /usr/local/lsws/admin/html.open/view/inc/header.php
sed -i 's@//ajax.googleapis.com/ajax/libs/jquery/2.1.1/jquery.min.js@//apps.bdimg.com/libs/jquery/2.1.1/jquery.min.js@' /usr/local/lsws/admin/html.open/view/inc/header.php
sed -i 's@//ajax.googleapis.com/ajax/libs/jqueryui/1.11.1/jquery-ui.min.js@//apps.bdimg.com/libs/jqueryui/1.9.2/jquery-ui.min.js@' /usr/local/lsws/admin/html.open/view/inc/header.php

cd $cur_dir
git clone https://github.com/FRiCKLE/ngx_cache_purge.git
git clone https://bitbucket.org/nginx-goodies/nginx-sticky-module-ng.git

cd $cur_dir
tar zxvf nginx-1.18.0.tar.gz
cd nginx-1.18.0/
./configure \
--user=www \
--group=www \
--prefix=/usr/local/nginx \
--add-module=${cur_dir}/ngx_cache_purge \
--add-module=${cur_dir}/nginx-sticky-module-ng \
--with-http_stub_status_module \
--with-http_v2_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_ssl_preread_module  \
--with-http_ssl_module \
--with-http_gzip_static_module \
--with-http_gunzip_module \
--with-http_realip_module \
--with-http_flv_module \
--with-http_addition_module \
--with-http_sub_module \
--with-http_mp4_module \
--with-http_secure_link_module \
--with-http_image_filter_module \
--with-pcre=${cur_dir}/pcre \
--with-openssl=${cur_dir}/openssl \
--with-ipv6 \
--with-file-aio \
--with-ld-opt="-ljemalloc" \
--with-cc-opt='-O2'
make -j2 && make install
cd ../
ln -s /usr/local/nginx/sbin/nginx /usr/bin/nginx
echo "============================web+pcre install completed================================="

mysqlphp(){
echo "============================mysql install=================================="
cd $cur_dir
tar zxvf mariadb-10.5.8.tar.gz
cd mariadb-10.5.8/
cmake . -DCMAKE_INSTALL_PREFIX=/usr/local/mysql \
-DMYSQL_DATADIR=/usr/local/mysql/data \
-DEXTRA_CHARSETS=all \
-DDEFAULT_CHARSET=utf8mb4 \
-DDEFAULT_COLLATION=utf8mb4_general_ci \
-DWITH_READLINE=1 \
-DENABLED_LOCAL_INFILE=1 \
-DWITH_EMBEDDED_SERVER=1 \
-DCMAKE_EXE_LINKER_FLAGS="-ljemalloc" \
-DWITHOUT_TOKUDB=1
make -j2 && make install
cd ../

cat > /etc/my.cnf<<EOF
[client]
#password	= your_password
port		= 3306
socket		= /tmp/mysql.sock

[mysqld]
port		= 3306
socket		= /tmp/mysql.sock
datadir = /usr/local/mysql/data
default_storage_engine = InnoDB
skip-external-locking
key_buffer_size = 8M
max_allowed_packet = 100G
table_open_cache = 32
sort_buffer_size = 256K
net_buffer_length = 4K
read_buffer_size = 128K
read_rnd_buffer_size = 256K
myisam_sort_buffer_size = 4M
thread_cache_size = 4
query_cache_size = 0M
tmp_table_size = 8M
sql-mode=NO_ENGINE_SUBSTITUTION,STRICT_TRANS_TABLES

#skip-name-resolve
max_connections = 500
max_connect_errors = 100
open_files_limit = 65535

log-bin=mysql-bin
binlog_format=mixed
server-id = 1
slow_query_log=1
slow-query-log-file=/usr/local/mysql/data/mysql-slow.log
long_query_time=3
#log_queries_not_using_indexes=on


innodb_data_home_dir = /usr/local/mysql/data
innodb_data_file_path = ibdata1:10M:autoextend
innodb_log_group_home_dir = /usr/local/mysql/data
innodb_buffer_pool_size = 16M
innodb_log_file_size = 5M
innodb_log_buffer_size = 8M
innodb_flush_log_at_trx_commit = 0
innodb_lock_wait_timeout = 50

[mysqldump]
quick
max_allowed_packet = 500M

[mysql]
no-auto-rehash

[myisamchk]
key_buffer_size = 20M
sort_buffer_size = 20M
read_buffer = 2M
write_buffer = 2M

[mysqlhotcopy]
interactive-timeout
EOF

#chown -R mysql:mysql /usr/local/mysql
mkdir -p /usr/local/mysql/data
chown -R mysql:mysql /usr/local/mysql/data
/usr/local/mysql/scripts/mysql_install_db --defaults-file=/etc/my.cnf --basedir=/usr/local/mysql --datadir=/usr/local/mysql/data --user=mysql
chgrp -R mysql /usr/local/mysql/.

#cp /usr/local/mysql/support-files/my-large.cnf /etc/my.cnf
cp /usr/local/mysql/support-files/mysql.server /etc/init.d/mysql
chmod +x /etc/init.d/mysql
sed -i 's/$bindir\/mysqld_safe /&--defaults-file="\/etc\/my.cnf" /' /etc/init.d/mysql
sed -i '/case "$mode" in/i\ulimit -s unlimited' /etc/init.d/mysql
rm -rf /etc/ld.so.conf.d/{mysql,mariadb,percona,alisql}*.conf
cat > /etc/ld.so.conf.d/mysql.conf<<EOF
/usr/local/mysql/lib
EOF
ldconfig

ln -sf /usr/local/mysql/lib/mysql /usr/lib/mysql
ln -sf /usr/local/mysql/include/mysql /usr/include/mysql
/etc/init.d/mysql start
/usr/local/mysql/bin/mysqladmin -u root password "$mysqlrootpwd"

	ln -sf /usr/local/mysql/bin/mysql /usr/bin/mysql
	ln -sf /usr/local/mysql/bin/mysqldump /usr/bin/mysqldump
	ln -sf /usr/local/mysql/bin/myisamchk /usr/bin/myisamchk
	ln -sf /usr/local/mysql/bin/mysqld_safe /usr/bin/mysqld_safe
	ln -sf /usr/local/mysql/bin/mysqlcheck /usr/bin/mysqlcheck
	ln -sf /usr/local/mysql/bin/mysql_config /usr/bin/mysql_config
	
	rm -f /usr/lib/libmysqlclient.so.16
	rm -f /usr/lib64/libmysqlclient.so.16
	rm -f /usr/lib/libmysqlclient.so.18
	rm -f /usr/lib64/libmysqlclient.so.18
	rm -f /usr/lib/libmysqlclient.so.20
	rm -f /usr/lib64/libmysqlclient.so.20
	rm -f /usr/lib/libmysqlclient.so.21
	rm -f /usr/lib64/libmysqlclient.so.21
	
	if [ -f "/usr/local/mysql/lib/libmysqlclient.so.18" ];then
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.20
	elif [ -f "/usr/local/mysql/lib/mysql/libmysqlclient.so.18" ];then
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.18 /usr/lib64/libmysqlclient.so.20
	elif [ -f "/usr/local/mysql/lib/libmysqlclient.so.16" ];then
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.20
	elif [ -f "/usr/local/mysql/lib/mysql/libmysqlclient.so.16" ];then
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.16 /usr/lib64/libmysqlclient.so.20
	elif [ -f "/usr/local/mysql/lib/libmysqlclient_r.so.16" ];then
		ln -sf /usr/local/mysql/lib/libmysqlclient_r.so.16 /usr/lib/libmysqlclient_r.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient_r.so.16 /usr/lib64/libmysqlclient_r.so.16
	elif [ -f "/usr/local/mysql/lib/mysql/libmysqlclient_r.so.16" ];then
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient_r.so.16 /usr/lib/libmysqlclient_r.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient_r.so.16 /usr/lib64/libmysqlclient_r.so.16
	elif [ -f "/usr/local/mysql/lib/libmysqlclient.so.20" ];then
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.20
	elif [ -f "/usr/local/mysql/lib/libmysqlclient.so.21" ];then
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib64/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib/libmysqlclient.so.21
		ln -sf /usr/local/mysql/lib/libmysqlclient.so.21 /usr/lib64/libmysqlclient.so.21
	elif [ -f "/usr/local/mysql/lib/libmariadb.so.3" ]; then
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib64/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib/libmysqlclient.so.21
		ln -sf /usr/local/mysql/lib/libmariadb.so.3 /usr/lib64/libmysqlclient.so.21
	elif [ -f "/usr/local/mysql/lib/mysql/libmysqlclient.so.20" ];then
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.16
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.18
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib/libmysqlclient.so.20
		ln -sf /usr/local/mysql/lib/mysql/libmysqlclient.so.20 /usr/lib64/libmysqlclient.so.20
	fi

	/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "drop database test";
	/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "delete from mysql.user where user='';"
	/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "flush privileges;"

#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$mysqlrootpwd');"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "UPDATE mysql.user SET Password=PASSWORD('$mysqlrootpwd') WHERE User='root';"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "DELETE FROM mysql.user WHERE User='';"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "DROP USER ''@'%';"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "DROP DATABASE IF EXISTS test;"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
#/usr/local/mysql/bin/mysql -uroot -p$mysqlrootpwd -e "FLUSH PRIVILEGES;"

/etc/init.d/mysql restart
/etc/init.d/mysql stop
echo "============================mysql intall completed========================="

echo "============================php74+memcache install======================"
cd $cur_dir
#wget -c https://libzip.org/download/libzip-1.7.3.tar.gz
#tar zxvf libzip-1.7.3.tar.gz
#cd libzip-1.7.3/
#mkdir build && cd build
#cmake ..
#make -j2 && make install
#ln -s /usr/local/libzip/lib64/pkgconfig/libzip.pc /usr/local/lib/pkgconfig/libzip.pc
#ln -s /usr/local/libzip/lib64/libzip.so /usr/local/lib/libzip.so
#ln -s /usr/local/libzip/lib64/libzip.so.5 /usr/local/lib/libzip.so.5
#ln -s /usr/local/libzip/lib64/libzip.so.5.3 /usr/local/lib/libzip.so.5.3
#export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig/:$PKG_CONFIG_PATH
#ldconfig

mkdir libzip
cd libzip
wget -O libzip5-1.7.3-1.rpm http://rpmfind.net/linux/remi/enterprise/7/remi/x86_64/libzip5-1.7.3-1.el7.remi.x86_64.rpm
wget -O libzip5-devel-1.7.3-1.rpm http://rpmfind.net/linux/remi/enterprise/7/remi/x86_64/libzip5-devel-1.7.3-1.el7.remi.x86_64.rpm
wget -O libzip5-tools-1.7.3-1.rpm http://rpmfind.net/linux/remi/enterprise/7/remi/x86_64/libzip5-tools-1.7.3-1.el7.remi.x86_64.rpm
yum install * -y
cd ../

cd $cur_dir
#export PHP_AUTOCONF=/usr/local/bin/autoconf
#export PHP_AUTOHEADER=/usr/local/bin/autoheader
tar zxvf php-7.4.11.tar.gz
cd php-7.4.11/
#./buildconf --force
./configure --prefix=/usr/local/php74 \
--with-config-file-path=/usr/local/php74/etc \
--enable-fpm \
--enable-xml \
--enable-bcmath \
--enable-shmop \
--enable-sysvsem \
--enable-inline-optimization \
--enable-mbregex \
--enable-mbstring \
--enable-ftp \
--enable-gd \
--enable-pcntl \
--enable-intl \
--enable-sockets \
--enable-soap \
--enable-exif \
--enable-opcache \
--enable-mysqlnd \
--enable-litespeed \
--with-fpm-user=www \
--with-fpm-group=www \
--with-mysqli=mysqlnd \
--with-pdo-mysql=mysqlnd \
--with-iconv-dir \
--with-freetype \
--with-jpeg \
--with-zlib \
--with-curl \
--with-openssl \
--with-mhash \
--with-xmlrpc \
--with-gettext \
--with-xsl \
--with-webp \
--with-zip \
--disable-rpath \
--disable-fileinfo
make ZEND_EXTRA_LIBS='-liconv' -j2
make install

[ ! -e "/usr/local/php74/etc" ] && mkdir -p /usr/local/php74/etc
cp php.ini-production /usr/local/php74/etc/php.ini
cd ../

#ln -s /usr/local/php74/bin/php /usr/bin/php
#ln -s /usr/local/php74/bin/phpize /usr/bin/phpize
#ln -s /usr/local/php74/sbin/php-fpm /usr/bin/php-fpm

cd $cur_dir/php-7.4.11/ext/zip
/usr/local/php74/bin/phpize
./configure --with-php-config=/usr/local/php74/bin/php-config --enable-phalcon
make -j2 && make install
cd ../

#cd $cur_dir
#tar zxvf memcache-3.0.8.tgz
#cd memcache-3.0.8/
#/usr/local/php74/bin/phpize
#./configure --with-php-config=/usr/local/php74/bin/php-config
#make -j2 && make install
#cd ../

#cd $cur_dir
#tar zxvf redis-3.1.4.tgz
#cd redis-3.1.4/
#/usr/local/php74/bin/phpize
#./configure --with-php-config=/usr/local/php74/bin/php-config
#make -j2 && make install
#cd ../

#cd $cur_dir/php-7.4.11/ext/pdo_mysql/
#/usr/local/php74/bin/phpize
#./configure --with-php-config=/usr/local/php74/bin/php-config --with-pdo-mysql=/usr/local/mysql
#make -j2 && make install
#cd ../

# php extensions
#sed -i 's#; extension_dir = "./"#extension_dir = "/usr/local/php74/lib/php/extensions/no-debug-non-zts-20190902/"\nextension = "memcache.so"\n#' /usr/local/php74/etc/php.ini
sed -i 's#;extension_dir = "./"#extension_dir = "/usr/local/php74/lib/php/extensions/no-debug-non-zts-20190902/"\nextension = "memcache.so"\nextension = "redis.so"\nextension = "zip.so"\n#' /usr/local/php74/etc/php.ini
#sed -i 's#output_buffering = Off#output_buffering = On#' /usr/local/php74/etc/php.ini
sed -i 's/expose_php = On/expose_php = Off/g' /usr/local/php74/etc/php.ini
#sed -i 's@^request_order.*@request_order = "CGP"@' /usr/local/php74/etc/php.ini
sed -i 's/post_max_size =.*/post_max_size = 50M/g' /usr/local/php74/etc/php.ini
sed -i 's/upload_max_filesize =.*/upload_max_filesize = 50M/g' /usr/local/php74/etc/php.ini
sed -i 's/;date.timezone =.*/date.timezone = PRC/g' /usr/local/php74/etc/php.ini
sed -i 's/short_open_tag =.*/short_open_tag = On/g' /usr/local/php74/etc/php.ini
sed -i 's/;cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/g' /usr/local/php74/etc/php.ini
sed -i 's/max_execution_time =.*/max_execution_time = 300/g' /usr/local/php74/etc/php.ini
sed -i 's/disable_functions =.*/disable_functions = passthru,exec,system,putenv,chroot,chgrp,chown,shell_exec,popen,proc_open,pcntl_exec,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,imap_open,apache_setenv/g' /usr/local/php74/etc/php.ini

    #echo "Install ZendGuardLoader for PHP 5.6..."
    #cd $cur_dir
    #if is_64bit; then
        #wget -c http://downloads.zend.com/guard/7.0.0/zend-loader-php74.6-linux-x86_64.tar.gz
        #tar zxf zend-loader-php74.6-linux-x86_64.tar.gz
        #mkdir -p /usr/local/zend/
        #\cp zend-loader-php74.6-linux-x86_64/ZendGuardLoader.so /usr/local/zend/
        #\cp zend-loader-php74.6-linux-x86_64/opcache.so /usr/local/zend/
    #else
        #wget -c http://downloads.zend.com/guard/7.0.0/zend-loader-php74.6-linux-i386.tar.gz
        #tar zxf zend-loader-php74.6-linux-i386.tar.gz
        #mkdir -p /usr/local/zend/
        #\cp zend-loader-php74.6-linux-i386/ZendGuardLoader.so /usr/local/zend/
        #\cp zend-loader-php74.6-linux-i386/opcache.so /usr/local/zend/
    #fi
    
#edit php.ini
cat >>/usr/local/php74/etc/php.ini<<EOF
;[Zend ZendGuard Loader]
;zend_extension=/usr/local/zend/ZendGuardLoader.so
;zend_loader.enable = 1
;zend_loader.disable_licensing = 0
;zend_loader.obfuscation_level_support = 3
;zend_loader.license_path = 

[Zend Opcache]
zend_extension = /usr/local/php74/lib/php/extensions/no-debug-non-zts-20190902/opcache.so
opcache.enable = "1"
opcache.enable_cli = "0"
opcache.memory_consumption = "128"
opcache.interned_strings_buffer = "32"
opcache.max_accelerated_files = "10000"
opcache.revalidate_freq = "3"
opcache.fast_shutdown = "1"
EOF

#edit php-fpm.conf
cp $cur_dir/php-7.4.11/sapi/fpm/php-fpm.conf /usr/local/php74/etc/php-fpm.conf
sed -i 's/;pid =.*/pid = run/php-fpm74.pid/g' /usr/local/php74/etc/php-fpm.conf
mv /usr/local/php74/etc/php-fpm.d/www.conf.default /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/listen =.*/listen = /tmp/php-cgi74.sock/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/;listen.owner =.*/listen.owner = www/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/;listen.group =.*/listen.group = www/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/;listen.mode =.*/listen.mode = 0660/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/pm.max_children =.*/pm.max_children = 100/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/pm.start_servers =.*/pm.start_servers = 20/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/pm.min_spare_servers =.*/pm.min_spare_servers = 10/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/pm.max_spare_servers =.*/pm.max_spare_servers = 40/g' /usr/local/php74/etc/php-fpm.d/www.conf
sed -i 's/;security.limit_extensions =.*/security.limit_extensions = .php .asp/g' /usr/local/php74/etc/php-fpm.d/www.conf
echo "============================php74+memcache install completed======================"

echo "============================php70+memcache install======================"
cd $cur_dir
#export PHP_AUTOCONF=/usr/local/bin/autoconf
#export PHP_AUTOHEADER=/usr/local/bin/autoheader
tar zxvf php-7.0.33.tar.gz
cd php-7.0.33/
#./buildconf --force
./configure --prefix=/usr/local/php70 \
--with-config-file-path=/usr/local/php70/etc \
--enable-fpm \
--enable-xml \
--enable-bcmath \
--enable-shmop \
--enable-sysvsem \
--enable-inline-optimization \
--enable-mbregex \
--enable-mbstring \
--enable-ftp \
--enable-gd-native-ttf \
--enable-pcntl \
--enable-intl \
--enable-sockets \
--enable-zip \
--enable-soap \
--enable-exif \
--enable-opcache \
--enable-mysqlnd \
--with-fpm-user=www \
--with-fpm-group=www \
--with-mysqli=mysqlnd \
--with-pdo-mysql=mysqlnd \
--with-iconv-dir \
--with-freetype-dir \
--with-jpeg-dir \
--with-png-dir \
--with-zlib \
--with-libxml-dir=/usr \
--with-curl \
--with-mcrypt \
--with-gd \
--with-openssl \
--with-mhash \
--with-xmlrpc \
--with-gettext \
--with-xsl \
--with-litespeed \
--with-webp-dir \
--disable-rpath \
--disable-fileinfo
make ZEND_EXTRA_LIBS='-liconv' -j2
make install

[ ! -e "/usr/local/php70/etc" ] && mkdir -p /usr/local/php70/etc
cp php.ini-production /usr/local/php70/etc/php.ini
cd ../

#ln -s /usr/local/php70/bin/php /usr/bin/php
#ln -s /usr/local/php70/bin/phpize /usr/bin/phpize
#ln -s /usr/local/php70/sbin/php-fpm /usr/bin/php-fpm

cd $cur_dir/php-7.0.33/ext/zip
/usr/local/php70/bin/phpize
./configure --with-php-config=/usr/local/php70/bin/php-config --enable-phalcon
make -j2 && make install
cd ../

#cd $cur_dir
#tar zxvf pecl-memcache-php70.tgz
#cd pecl-memcache-php70/
#/usr/local/php70/bin/phpize
#./configure --with-php-config=/usr/local/php70/bin/php-config
#make -j2 && make install
#cd ../

#cd $cur_dir
#tar zxvf redis-3.1.4.tgz
#cd redis-3.1.4/
#/usr/local/php70/bin/phpize
#./configure --with-php-config=/usr/local/php70/bin/php-config
#make -j2 && make install
#cd ../

#cd $cur_dir/php-7.0.33/ext/pdo_mysql/
#/usr/local/php70/bin/phpize
#./configure --with-php-config=/usr/local/php70/bin/php-config --with-pdo-mysql=/usr/local/mysql
#make -j2 && make install
#cd ../

# php extensions
#sed -i 's#; extension_dir = "./"#extension_dir = "/usr/local/php70/lib/php/extensions/no-debug-non-zts-20170718/"\nextension = "memcache.so"\n#' /usr/local/php70/etc/php.ini
sed -i 's#;extension_dir = "./"#extension_dir = "/usr/local/php74/lib/php/extensions/no-debug-non-zts-20190902/"\nextension = "memcache.so"\nextension = "redis.so"\nextension = "zip.so"\n#' /usr/local/php70/etc/php.ini
#sed -i 's#output_buffering = Off#output_buffering = On#' /usr/local/php70/etc/php.ini
sed -i 's/expose_php = On/expose_php = Off/g' /usr/local/php70/etc/php.ini
#sed -i 's@^request_order.*@request_order = "CGP"@' /usr/local/php70/etc/php.ini
sed -i 's/post_max_size =.*/post_max_size = 50M/g' /usr/local/php70/etc/php.ini
sed -i 's/upload_max_filesize =.*/upload_max_filesize = 50M/g' /usr/local/php70/etc/php.ini
sed -i 's/;date.timezone =.*/date.timezone = PRC/g' /usr/local/php70/etc/php.ini
sed -i 's/short_open_tag =.*/short_open_tag = On/g' /usr/local/php70/etc/php.ini
sed -i 's/;cgi.fix_pathinfo=.*/cgi.fix_pathinfo=0/g' /usr/local/php70/etc/php.ini
sed -i 's/max_execution_time =.*/max_execution_time = 300/g' /usr/local/php70/etc/php.ini
sed -i 's/disable_functions =.*/disable_functions = passthru,exec,system,putenv,chroot,chgrp,chown,shell_exec,popen,proc_open,pcntl_exec,ini_alter,ini_restore,dl,openlog,syslog,readlink,symlink,popepassthru,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,imap_open,apache_setenv/g' /usr/local/php70/etc/php.ini

#    echo "Install ZendGuardLoader for PHP 7.0.33..."
#    cd $cur_dir
#    if is_64bit; then
#        wget -c http://downloads.zend.com/guard/7.0.0/ZendGuard-7.0.0-linux.gtk.x86_64.tar.gz
#        tar zxf ZendGuard-7.0.0-linux.gtk.x86_64.tar.gz
#        mkdir -p /usr/local/zend/
#        \cp ZendGuard-7.0.0-linux.gtk.x86_64/ZendGuardLoader.so /usr/local/zend/
#        \cp ZendGuard-7.0.0-linux.gtk.x86_64/opcache.so /usr/local/zend/
#    else
#        wget -c http://downloads.zend.com/guard/7.0.0/ZendGuard-7.0.0-linux.gtk.x86.tar.gz
#        tar zxf ZendGuard-7.0.0-linux.gtk.x86.tar.gz
#        mkdir -p /usr/local/zend/
#        \cp ZendGuard-7.0.0-linux.gtk.x86/ZendGuardLoader.so /usr/local/zend/
#        \cp ZendGuard-7.0.0-linux.gtk.x86/opcache.so /usr/local/zend/
#   fi
    
#edit php.ini
cat >>/usr/local/php70/etc/php.ini<<EOF
;[Zend ZendGuard Loader]
;zend_extension=/usr/local/zend/ZendGuardLoader.so
;zend_loader.enable = 1
;zend_loader.disable_licensing = 0
;zend_loader.obfuscation_level_support = 3
;zend_loader.license_path = 

[Zend Opcache]
zend_extension = /usr/local/php70/lib/php/extensions/no-debug-non-zts-20151012/opcache.so
opcache.enable = "1"
opcache.enable_cli = "0"
opcache.memory_consumption = "128"
opcache.interned_strings_buffer = "32"
opcache.max_accelerated_files = "10000"
opcache.revalidate_freq = "3"
opcache.fast_shutdown = "1"
EOF

#edit php-fpm.conf
cp $cur_dir/php-7.0.33/sapi/fpm/php-fpm.conf /usr/local/php70/etc/php-fpm.conf
sed -i 's/;pid =.*/pid = run/php-fpm70.pid/g' /usr/local/php70/etc/php-fpm.conf
mv /usr/local/php70/etc/php-fpm.d/www.conf.default /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/listen =.*/listen = /tmp/php-cgi70.sock/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/;listen.owner =.*/listen.owner = www/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/;listen.group =.*/listen.group = www/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/;listen.mode =.*/listen.mode = 0660/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/pm.max_children =.*/pm.max_children = 100/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/pm.start_servers =.*/pm.start_servers = 20/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/pm.min_spare_servers =.*/pm.min_spare_servers = 10/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/pm.max_spare_servers =.*/pm.max_spare_servers = 40/g' /usr/local/php70/etc/php-fpm.d/www.conf
sed -i 's/;security.limit_extensions =.*/security.limit_extensions = .php .asp/g' /usr/local/php70/etc/php-fpm.d/www.conf
echo "============================php70+memcache install completed======================"

echo "============================memcached install============================"
#cd $cur_dir
#tar zxvf libevent-2.1.8-stable.tar.gz
#cd libevent-2.1.8-stable/
#./configure --prefix=/usr/local/libevent
#make -j2 && make install
#cd ../
#	if is_64bit; then
#	ln -s /usr/local/libevent/lib/libevent-2.0.so.5 /usr/lib64/libevent-2.0.so.5
#	else
#	ln -s /usr/local/libevent/lib/libevent-2.0.so.5 /usr/lib/libevent-2.0.so.5
#	fi

cd $cur_dir
tar zxvf memcached-1.6.8.tar.gz
cd memcached-1.6.8/
./configure --prefix=/usr/local/memcached
make -j2 && make install
cd ../
ln -sf /usr/local/memcached/bin/memcached /usr/bin/memcached

cd $cur_dir
git clone https://github.com/websupport-sk/pecl-memcache.git
cd pecl-memcache
/usr/local/php74/bin/phpize
./configure --with-php-config=/usr/local/php74/bin/php-config
make -j2 && make install
cd ../
rm -rf pecl-memcache

cd $cur_dir
git clone https://github.com/websupport-sk/pecl-memcache.git
cd pecl-memcache
#make clean
#make distclean
/usr/local/php70/bin/phpize
./configure --with-php-config=/usr/local/php70/bin/php-config
make -j2 && make install
cd ../

#/usr/local/memcached/bin/memcached -d -m 128 -u root -l 127.0.0.1 -p 11214 -c 65535 -P /tmp/memcached.pid
#cat >>/etc/rc.d/rc.local<<EOF
#/usr/local/memcached/bin/memcached -d -m 128 -u root -l 127.0.0.1 -p 11214 -c 65535 -P /tmp/memcached.pid
#EOF
#chmod 755 /etc/rc.d/rc.local

cd $cur_dir
tar zxvf redis-5.0.10.tar.gz
cd redis-5.0.10/
make PREFIX=/usr/local/redis install
mkdir -p /usr/local/redis/etc/
\cp redis.conf  /usr/local/redis/etc/
sed -i 's/daemonize no/daemonize yes/g' /usr/local/redis/etc/redis.conf
#        if ! grep -Eqi '^bind[[:space:]]*127.0.0.1' /usr/local/redis/etc/redis.conf; then
#            sed -i 's/^# bind 127.0.0.1/bind 127.0.0.1/g' /usr/local/redis/etc/redis.conf
#        fi
sed -i 's/# maxmemory <bytes>/maxmemory 1024M/g' /usr/local/redis/etc/redis.conf
sed -i 's@logfile ""@logfile /dev/null@' /usr/local/redis/etc/redis.conf
sed -i 's@pidfile.*@pidfile /var/run/redis.pid@' /usr/local/redis/etc/redis.conf
#sed -i 's@save 900 1@#save 900 1@' /usr/local/redis/etc/redis.conf
#sed -i 's@save 300 10@#save 300 10@' /usr/local/redis/etc/redis.conf
#sed -i 's@save 60 10000@#save 60 10000@' /usr/local/redis/etc/redis.conf
cd ../
#echo never > /sys/kernel/mm/transparent_hugepage/enabled
#chmod +x /etc/init.d/redis
#chown -R redis.redis /usr/local/redis

cd $cur_dir
git clone https://github.com/phpredis/phpredis.git
cd phpredis
/usr/local/php74/bin/phpize
./configure --with-php-config=/usr/local/php74/bin/php-config
make -j2 && make install
cd ../
rm -rf phpredis

cd $cur_dir
git clone https://github.com/phpredis/phpredis.git
cd phpredis
#make clean
#make distclean
/usr/local/php70/bin/phpize
./configure --with-php-config=/usr/local/php70/bin/php-config
make -j2 && make install
cd ../
echo "===========================memcached install completed===================="
}
#mysqlphp

echo "===========================add web and php-fpm on startup============================"
echo "Copy new start file......"
#cp $cur_dir/php-7.4.11/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm74
#chmod +x /etc/init.d/php-fpm74
#cp $cur_dir/php-7.0.33/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm70
#chmod +x /etc/init.d/php-fpm70

#cp $cur_dir/php-7.4.11/sapi/litespeed/php /usr/local/lsws/fcgi-bin/lsphp74
#cp $cur_dir/php-7.0.33/sapi/litespeed/php /usr/local/lsws/fcgi-bin/lsphp70

if [ -s nginx ]; then
  echo "nginx [found]"
  else
  echo "Error: nginx not found!!!download now......"
  wget -c http://downloads.sourceforge.net/filesave/nginx
fi
cp nginx /etc/init.d/nginx
chmod +x /etc/init.d/nginx

#if [ -s redis ]; then
#  echo "redis [found]"
#  else
#  echo "Error: redis not found!!!download now......"
#  wget -c http://downloads.sourceforge.net/filesave/redis
#fi
#cp redis /etc/init.d/redis
#chmod +x /etc/init.d/redis

#if [ -s ltmp ]; then
#  echo "ltmp [found]"
#  else
#  echo "Error: ltmp not found!!!download now......"
#  wget -c http://downloads.sourceforge.net/filesave/ltmp
#fi
#cp ltmp /root/ltmp
#chmod +x /root/ltmp

#chkconfig --level 345 php-fpm74 on
#chkconfig --level 345 php-fpm70 on
chkconfig --level 345 nginx on
#chkconfig --level 345 lsws on
#chkconfig --level 345 mysql on
#chkconfig --level 345 redis on
echo "===========================add web and php-fpm on startup completed===================="
echo "Starting lcmp..."
#/etc/init.d/mysql start
#/etc/init.d/lsws start
#/etc/init.d/redis start
/etc/init.d/nginx start
#/etc/init.d/php-fpm74 start
#/etc/init.d/php-fpm70 start

#add 80 port to iptables
#if [ -s /sbin/iptables ]; then
#/sbin/iptables -I INPUT -p tcp --dport 80 -j ACCEPT
#/sbin/iptables-save
#fi
echo "===========================Check install ==================================="
clear
if [ -s /usr/local/nginx ]; then
  echo "/usr/local/nginx [found]"
  else
  echo "Error: /usr/local/nginx not found!!!"
fi

if [ -s /usr/local/php74 ]; then
  echo "/usr/local/php74 [found]"
  else
  echo "Error: /usr/local/php74 not found!!!"
fi

if [ -s /usr/local/php70 ]; then
  echo "/usr/local/php70 [found]"
  else
  echo "Error: /usr/local/php70 not found!!!"
fi

if [ -s /usr/local/mysql ]; then
  echo "/usr/local/mysql [found]"
  else
  echo "Error: /usr/local/mysql not found!!!"
fi

Set_Firewall(){
	sshPort=$(cat /etc/ssh/sshd_config | grep 'Port '|awk '{print $2}')
		if [ -f "/etc/init.d/iptables" ];then
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 6526 -j ACCEPT
			iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport ${sshPort} -j ACCEPT
			iptables -A INPUT -p icmp --icmp-type any -j ACCEPT
			iptables -A INPUT -s localhost -d localhost -j ACCEPT
			iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
			iptables -P INPUT DROP
			service iptables save
			sed -i "s#IPTABLES_MODULES=\"\"#IPTABLES_MODULES=\"ip_conntrack_netbios_ns ip_conntrack_ftp ip_nat_ftp\"#" /etc/sysconfig/iptables-config
			iptables_status=$(service iptables status | grep 'not running')
			if [ "${iptables_status}" == '' ];then
				service iptables restart
			fi
		else
			AliyunCheck=$(cat /etc/redhat-release|grep "Aliyun Linux")
			[ "${AliyunCheck}" ] && return
			yum install firewalld -y
			[ "${Centos8Check}" ] && yum reinstall python3-six -y
			systemctl enable firewalld
			systemctl start firewalld
			firewall-cmd --set-default-zone=public > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=22/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=80/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=443/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=6526/tcp > /dev/null 2>&1
			firewall-cmd --permanent --zone=public --add-port=${sshPort}/tcp > /dev/null 2>&1
			firewall-cmd --reload
		fi
}
Set_Firewall
netstat -ntl

	if [ "${Centos8Check}" ];then
		sed -i 's/Port 22/Port 6526/g' /etc/ssh/sshd_config
		service sshd restart
		else
		sed -i 's/#Port 22/Port 6526/g' /etc/ssh/sshd_config
		service sshd restart
	fi
echo "===========================Check install ================================"
if [ -s /usr/local/nginx ] && [ -s /usr/local/php74 ] && [ -s /usr/local/php70 ] && [ -s /usr/local/mysql ]; then
  echo "Ok!"
else
  echo "Sorry,Failed to install lcmp!"
fi
fi