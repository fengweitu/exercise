package main
//
//import (
//	//"AiGENT/src/aigent/metric"
//	//"AiGENT/src/common/log"
//	"database/sql"
//	"fmt"
//	"log"
//	"strconv"
//
//	_ "github.com/godror/godror"
//)
//
//const (
//	driverName    = "godror"
//	userName      = "system"
//	passWord       = "oracle"
//	connectString = "192.168.30.39:49999/XE"
//	libDir = "C:\\Users\\tfw\\go\\soft\\instantclient"
//)
//
//const (
//	TypeMetricOracleInfo   = "type_metric_oracle_info"
//	MetricOracleInfoUsages = "oracle数据库参数(Oracle_Info)"
//
//	LibraryCacheHitRate = "library_cache_hit_rate"
//	SGADataCacheHitRate = "sga_data_cache_hit_rate"
//	MemSortRate = "mem_sort_rate"
//	DictionaryCacheHitRate = "dictionary_cache_hit_rate"
//	RedoLogCacheHitRate = "redo_log_cache_hit_rate"
//
//)
//
//type OracleInfoStats struct {
//	//ps PS
//}
//
//type oracleDB struct {
//	DB *sql.DB
//}
//
//func (o OracleInfoStats) Name() string {
//	return TypeMetricOracleInfo
//}
//
//func (o OracleInfoStats) Tags() []string {
//	return []string{}
//}
//
//func (o OracleInfoStats) Usages() string {
//	return MetricOracleInfoUsages
//}
//
//func (o OracleInfoStats) Config() map[string]interface{} {
//	return nil
//}
//
//func (o OracleInfoStats) Collect() ([]map[string]interface{}, error) {
//	data:=make([]map[string]interface{},0)
//	db,err:=conn()
//	if err != nil {
//		log.Fatal(err)
//		//log.Error(err)
//		return nil,err
//	}
//	libraryCacheHitRate:=db.getLibraryCacheHitRate()
//	sgaDataCacheHitRate:=db.getSGADataCacheHitRate()
//	memSortRate:=db.getMemSortRate()
//	dictionaryCacheHitRate:=db.getDictionaryCacheHitRate()
//	redoLogCacheHitRate:=db.getRedoLogCacheHitRate()
//	fields:=map[string]interface{}{
//		LibraryCacheHitRate: libraryCacheHitRate,
//		SGADataCacheHitRate: sgaDataCacheHitRate,
//		MemSortRate: memSortRate,
//		DictionaryCacheHitRate: dictionaryCacheHitRate,
//		RedoLogCacheHitRate: redoLogCacheHitRate,
//	}
//	data=append(data, fields)
//	return data,nil
//}
//
////func init() {
////	metric.Add(TypeMetricOracleInfo, func() metric.Collector {
////		return &OracleInfoStats{
////			ps: newSystemPS(),
////		}
////	})
////}
//
//// 库缓存命中率,未完成
//func (db *oracleDB)getLibraryCacheHitRate()float64 {
//	librarySql:="select (1-(sum(reloads)/sum(pins)))*100 LIBRARY_CACHE_HITRATE from v$librarycache"
//	data,err:=db.execSQL(librarySql,"LIBRARY_CACHE_HITRATE")
//	if err != nil {
//		log.Fatal(err)
//		return 0
//	}
//	return data
//}
//
////SGA数据库缓存命中率
//func (db *oracleDB) getSGADataCacheHitRate()float64 {
//	dataSql:="select (1 - (phy.value / (cur.value + con.value))) * 100 SGA_DATA_CACHE_HITRATE from v$sysstat cur, v$sysstat con, v$sysstat phy where cur.name = 'db block gets' and con.name = 'consistent gets' and phy.name = 'physical reads'"
//
//	data,err:=db.execSQL(dataSql,"SGA_DATA_CACHE_HITRATE")
//	if err != nil {
//		log.Fatal(err)
//		return 0
//	}
//	return data
//
//}
//
//// 内存排序比率
//func (db *oracleDB) getMemSortRate()float64{
//	memSql:="SELECT VALUE FROM v$sysstat WHERE name IN ('sorts (memory)')"
//	memSort,err:=db.execSQL(memSql,"VALUE")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	diskSql:="SELECT VALUE FROM v$sysstat WHERE name IN ('sorts (disk)')"
//	diskSort,err:=db.execSQL(diskSql,"VALUE")
//	if err != nil {
//		log.Fatal(err)
//	}
//	if (memSort+diskSort)==0 {
//		log.Fatal(err)
//		return 0
//	}
//	memSortRatio:=memSort/(memSort+diskSort)*100
//	return memSortRatio
//
//}
//
//// 词典缓存命中率
//func (db *oracleDB)getDictionaryCacheHitRate()float64 {
//	dicSql:="select (1 - (sum(getmisses)/sum(gets)))*100 DICT_CACHE_HIT_RATIO from v$rowcache"
//	data,err:=db.execSQL(dicSql,"DICT_CACHE_HIT_RATIO")
//	if err != nil {
//		log.Fatal(err)
//		return 0
//	}
//	return data
//}
//
//// 重做日志缓存命中率
//func (db *oracleDB)getRedoLogCacheHitRate()float64{
//	logSql:="select ((req.value*5000)/entries.value)*100 REDO_LOG_CACHE_HITRATE from v$sysstat req,v$sysstat entries where req.name = 'redo log space requests' and entries.name='redo entries'"
//	data,err:=db.execSQL(logSql,"DICT_CACHE_HIT_RATIO")
//	if err != nil {
//		log.Fatal(err)
//		return 0
//	}
//	return data
//}
//
//
//// 连接oracle数据库
//func conn() (oracleDB,error) {
//	connStr := fmt.Sprintf("user=%s password=%s connectString=%s libDir=%s", userName, passWord, connectString,libDir)
//	db, err := sql.Open(driverName, connStr)
//	if err != nil {
//		return oracleDB{}, err
//	}
//	return oracleDB{db}, nil
//}
//
//// 执行SQL语句，并获取指定值
//func (db *oracleDB)execSQL(sqlStr string,key string) (float64,error) {
//	rows,err:=db.DB.Query(sqlStr)
//	if err != nil {
//		return 0,err
//	}
//	defer rows.Close()
//	var value string
//	for rows.Next(){
//		errS:=rows.Scan(&value)
//		if errS != nil {
//			return 0,errS
//		}
//	}
//	num,errP:=strconv.ParseFloat(value,10)
//	if errP != nil {
//		return 0,errP
//	}
//	return num, nil
//}
//
