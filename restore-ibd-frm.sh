#!/bin/sh

## Authors 
## =======
##
## **this script**
##   - Nicolas Fouville (saelyx) : https://github.com/secureinfo42/scripts
##
## **the process**
##   - Luqman Sungkar (luqmansungkar) : https://gist.github.com/luqmansungkarW/a291fa4e9bf4b2b0dd011ad286cbcb13
##
## **the tool : dbsake**
##   - Andrew Garner (abg) : https://github.com/abg

###################################################################################################
#
# Constants
#
##

APP="restore-ibd-frm.sh"
PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin" # :/opt/lampp/bin:/opt/lampp/sbin"



###################################################################################################
#
# Args
#
##

# DB="base_exemple"
# BKP_DIR="/path/to/frm+ibd-files/"

if [ $# -eq 3 -o $# -eq 4 ]; then
  BKP_DIR="$1"
  DB="$2"
  DB_USER="$3"
  DB_PASS="$4"
else 
  echo "Usage: $APP </path/to/frm+ibd-files> <database_name>  <db_user> [db_pass]"
  exit
fi



###################################################################################################
#
# Sys-settings 
#
##

LOG="$BKP_DIR/$DB-import.log"

DST_DIR="/opt/lampp/var/mysql/$DB" # /var/lib/mysql
MYSQL_BIN="/opt/lampp/bin/mysql" # /usr/bin/mysql

MYSQL_GROUP="mysql"
MYSQL_USER="mysql"



###################################################################################################
#
# Funcz
#
##

function error() {
  echo "Error: $1" >&2
  exit $2
}
 
function db_exec() {
  [ "x$DB_PASS" = "x" ] && $MYSQL_BIN -u$DB_USER $1
  [ "x$DB_PASS" = "x" ] || $MYSQL_BIN -u$DB_USER -p$DB_PASS $1
}

function install_dbsake() {
  curl -s http://get.dbsake.net > /usr/local/bin/dbsake
  chmod u+x /usr/local/bin/dbsake
  # dbsake --version
}



###################################################################################################
#
# Some checks
#
##

which dbsake >/dev/null 2>&1 || install_dbsake
[ "$(whoami)" = "root" ]     || error "need to be root." 1

printf "\n# Rebuilding database '$DB'"

printf "\n## Started @$(date)\n"

printf "DROP DATABASE $DB;"  |db_exec 2>&1 >> $LOG || error "can't connect do database (check instance)." 2
printf "CREATE DATABASE $DB;"|db_exec 2>&1 >> $LOG

cd "$BKP_DIR" || error "can't cd to '$BKP_DIR'" 2

printf "\n %-40s | %s" "Table name" "Imported"
printf "\n %-40s | %s" "----------" "--------"
for tbl_frm in *.frm ; do

  tbl_name=`echo $tbl_frm|cut -d. -f1` # my_table.frm -> my_table

  printf "\n %-40s | " "$tbl_name"
  dbsake frmdump $tbl_frm | db_exec $DB || error "dbsake failed to import structure."

  printf "ALTER TABLE $tbl_name DISCARD TABLESPACE;"|db_exec $DB 2>&1 >> $LOG
  sync ; sleep .1

  rm -f "$DST_DIR/$tbl_name.ibd"
  cp -f $tbl_name.ibd "$DST_DIR/"
  chown -R $MYSQL_USER:$MYSQL_GROUP "$DST_DIR"
  chmod 660 "$DST_DIR/$tbl_name.ibd"

  printf "ALTER TABLE $tbl_name IMPORT TABLESPACE;"|db_exec $DB 2>&1 >> $LOG

  num=$(printf "SELECT COUNT(*) FROM $tbl_name;"|db_exec $DB 2>&1|tail -n1)
  printf "%s" "$num"

  sync ; sleep .1

done

printf "\n"
printf "\n## Finished @$(date)"
printf "\n"

