-- MySQL dump 10.13  Distrib 8.0.25, for Win64 (x86_64)
--
-- Host: localhost    Database: react_reply
-- ------------------------------------------------------
-- Server version	8.0.25

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `api_user`
--

DROP TABLE IF EXISTS `api_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `api_user` (
  `client_id` varchar(255) NOT NULL,
  `client_secret` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`client_id`),
  UNIQUE KEY `client_id_UNIQUE` (`client_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `api_user`
--

LOCK TABLES `api_user` WRITE;
/*!40000 ALTER TABLE `api_user` DISABLE KEYS */;
INSERT INTO `api_user` VALUES ('client_id','$2a$10$MyYOQTzL5C7m2youJnGMg..2Z1uPiEP0l7VAPNH/JsBv3MXNSPeVO');
/*!40000 ALTER TABLE `api_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `comment`
--

DROP TABLE IF EXISTS `comment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `comment` (
  `no` int NOT NULL AUTO_INCREMENT,
  `parent_no` int DEFAULT NULL,
  `content` text,
  `writedate` timestamp NULL DEFAULT NULL,
  `user_no` int DEFAULT NULL,
  PRIMARY KEY (`no`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `comment`
--

LOCK TABLES `comment` WRITE;
/*!40000 ALTER TABLE `comment` DISABLE KEYS */;
INSERT INTO `comment` VALUES (1,101,'댓글','2023-11-23 23:27:26',3),(2,101,'댓글2','2023-11-23 23:27:33',3),(3,106,'aaaaa','2023-11-24 01:38:54',3),(5,106,'댓글','2023-11-24 01:42:11',3),(6,106,'댓글','2023-11-24 01:42:13',3),(7,106,'댓글','2023-11-24 01:42:15',3),(8,106,'댓글','2023-11-24 01:42:17',3),(9,106,'댓글','2023-11-24 01:42:19',3),(10,106,'댓글','2023-11-24 01:42:22',3),(11,106,'댓글','2023-11-24 01:42:24',3),(17,106,'ㅋㅋㅋ','2024-02-02 03:47:12',3),(18,106,'test','2024-02-02 05:23:13',3),(19,106,'ㅎㅎㅎ','2024-02-02 05:25:06',3),(20,106,'ㄱㄱㄱ','2024-02-02 05:25:42',3),(28,121,'111','2024-02-02 06:57:44',3),(29,121,'222','2024-02-02 06:57:46',3),(30,121,'333','2024-02-02 08:27:06',3),(31,132,'첫번째 댓글','2024-02-02 08:27:36',3),(32,132,'두번째 댓글','2024-02-02 08:36:46',3);
/*!40000 ALTER TABLE `comment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reply`
--

DROP TABLE IF EXISTS `reply`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `reply` (
  `no` int NOT NULL AUTO_INCREMENT,
  `title` varchar(100) DEFAULT NULL,
  `content` text,
  `writedate` timestamp NULL DEFAULT NULL,
  `viewcnt` int DEFAULT NULL,
  `filename_org` varchar(255) DEFAULT NULL,
  `filename_real` varchar(255) DEFAULT NULL,
  `likecnt` int DEFAULT NULL,
  `user_no` int DEFAULT NULL,
  `gno` int DEFAULT NULL,
  `ono` int DEFAULT NULL,
  `nested` int DEFAULT NULL,
  PRIMARY KEY (`no`)
) ENGINE=InnoDB AUTO_INCREMENT=136 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reply`
--

LOCK TABLES `reply` WRITE;
/*!40000 ALTER TABLE `reply` DISABLE KEYS */;
INSERT INTO `reply` VALUES (1,'제목1','내용1','2024-02-27 06:22:19',1,NULL,NULL,0,NULL,1,0,0),(2,'제목2','내용2','2023-11-23 03:09:34',0,NULL,NULL,0,0,2,0,0),(3,'제목3','내용3','2023-11-23 03:09:34',0,NULL,NULL,0,0,3,0,0),(4,'제목4','내용4','2023-11-23 03:09:34',0,NULL,NULL,0,0,4,0,0),(5,'제목5','내용5','2023-11-23 03:09:34',0,NULL,NULL,0,0,5,0,0),(6,'제목6','내용6','2023-11-23 03:09:34',0,NULL,NULL,0,0,6,0,0),(7,'제목7','내용7','2023-11-23 03:09:34',0,NULL,NULL,0,0,7,0,0),(8,'제목8','내용8','2023-11-23 03:09:34',0,NULL,NULL,0,0,8,0,0),(9,'제목9','내용9','2023-11-23 03:09:34',0,NULL,NULL,0,0,9,0,0),(10,'제목10','내용10','2023-11-23 03:09:34',0,NULL,NULL,0,0,10,0,0),(11,'제목11','내용11','2023-11-23 03:09:34',0,NULL,NULL,0,0,11,0,0),(12,'제목12','내용12','2023-11-23 03:09:34',0,NULL,NULL,0,0,12,0,0),(13,'제목13','내용13','2023-11-23 03:09:34',0,NULL,NULL,0,0,13,0,0),(14,'제목14','내용14','2023-11-23 03:09:34',0,NULL,NULL,0,0,14,0,0),(15,'제목15','내용15','2023-11-23 03:09:34',0,NULL,NULL,0,0,15,0,0),(16,'제목16','내용16','2023-11-23 03:09:34',0,NULL,NULL,0,0,16,0,0),(17,'제목17','내용17','2023-11-23 03:09:34',0,NULL,NULL,0,0,17,0,0),(18,'제목18','내용18','2023-11-23 03:09:34',0,NULL,NULL,0,0,18,0,0),(19,'제목19','내용19','2023-11-23 03:09:34',0,NULL,NULL,0,0,19,0,0),(20,'제목20','내용20','2023-11-23 03:09:34',0,NULL,NULL,0,0,20,0,0),(21,'제목21','내용21','2023-11-23 03:09:34',0,NULL,NULL,0,0,21,0,0),(22,'제목22','내용22','2023-11-23 03:09:34',0,NULL,NULL,0,0,22,0,0),(23,'제목23','내용23','2023-11-23 03:09:34',0,NULL,NULL,0,0,23,0,0),(24,'제목24','내용24','2023-11-23 03:09:34',0,NULL,NULL,0,0,24,0,0),(25,'제목25','내용25','2023-11-23 03:09:34',0,NULL,NULL,0,0,25,0,0),(26,'제목26','내용26','2023-11-23 03:09:34',0,NULL,NULL,0,0,26,0,0),(27,'제목27','내용27','2023-11-23 03:09:34',0,NULL,NULL,0,0,27,0,0),(28,'제목28','내용28','2023-11-23 03:09:34',0,NULL,NULL,0,0,28,0,0),(29,'제목29','내용29','2023-11-23 03:09:34',0,NULL,NULL,0,0,29,0,0),(30,'제목30','내용30','2023-11-23 03:09:34',0,NULL,NULL,0,0,30,0,0),(31,'제목31','내용31','2023-11-23 03:09:34',0,NULL,NULL,0,0,31,0,0),(32,'제목32','내용32','2023-11-23 03:09:34',0,NULL,NULL,0,0,32,0,0),(33,'제목33','내용33','2023-11-23 03:09:34',0,NULL,NULL,0,0,33,0,0),(34,'제목34','내용34','2023-11-23 03:09:34',0,NULL,NULL,0,0,34,0,0),(35,'제목35','내용35','2023-11-23 03:09:34',0,NULL,NULL,0,0,35,0,0),(36,'제목36','내용36','2023-11-23 03:09:34',0,NULL,NULL,0,0,36,0,0),(37,'제목37','내용37','2023-11-23 03:09:34',0,NULL,NULL,0,0,37,0,0),(38,'제목38','내용38','2023-11-23 03:09:34',0,NULL,NULL,0,0,38,0,0),(39,'제목39','내용39','2023-11-23 03:09:34',0,NULL,NULL,0,0,39,0,0),(40,'제목40','내용40','2023-11-23 03:09:34',0,NULL,NULL,0,0,40,0,0),(41,'제목41','내용41','2023-11-23 03:09:34',0,NULL,NULL,0,0,41,0,0),(42,'제목42','내용42','2023-11-23 03:09:34',0,NULL,NULL,0,0,42,0,0),(43,'제목43','내용43','2023-11-23 03:09:34',0,NULL,NULL,0,0,43,0,0),(44,'제목44','내용44','2023-11-23 03:09:34',0,NULL,NULL,0,0,44,0,0),(45,'제목45','내용45','2023-11-23 03:09:34',0,NULL,NULL,0,0,45,0,0),(46,'제목46','내용46','2023-11-23 03:09:34',0,NULL,NULL,0,0,46,0,0),(47,'제목47','내용47','2023-11-23 03:09:34',0,NULL,NULL,0,0,47,0,0),(48,'제목48','내용48','2023-11-23 03:09:34',0,NULL,NULL,0,0,48,0,0),(49,'제목49','내용49','2023-11-23 03:09:34',0,NULL,NULL,0,0,49,0,0),(50,'제목50','내용50','2023-11-23 03:09:34',0,NULL,NULL,0,0,50,0,0),(51,'제목51','내용51','2023-11-23 03:09:34',0,NULL,NULL,0,0,51,0,0),(52,'제목52','내용52','2023-11-23 03:09:34',0,NULL,NULL,0,0,52,0,0),(53,'제목53','내용53','2023-11-23 03:09:34',0,NULL,NULL,0,0,53,0,0),(54,'제목54','내용54','2023-11-23 03:09:34',0,NULL,NULL,0,0,54,0,0),(55,'제목55','내용55','2023-11-23 03:09:34',0,NULL,NULL,0,0,55,0,0),(56,'제목56','내용56','2023-11-23 03:09:34',0,NULL,NULL,0,0,56,0,0),(57,'제목57','내용57','2023-11-23 03:09:34',0,NULL,NULL,0,0,57,0,0),(58,'제목58','내용58','2023-11-23 03:09:34',0,NULL,NULL,0,0,58,0,0),(59,'제목59','내용59','2023-11-23 03:09:34',0,NULL,NULL,0,0,59,0,0),(60,'제목60','내용60','2023-11-23 03:09:34',0,NULL,NULL,0,0,60,0,0),(61,'제목61','내용61','2023-11-23 03:09:34',0,NULL,NULL,0,0,61,0,0),(62,'제목62','내용62','2023-11-23 03:09:34',0,NULL,NULL,0,0,62,0,0),(63,'제목63','내용63','2023-11-23 03:09:34',0,NULL,NULL,0,0,63,0,0),(64,'제목64','내용64','2023-11-23 03:09:34',0,NULL,NULL,0,0,64,0,0),(65,'제목65','내용65','2023-11-23 03:09:34',0,NULL,NULL,0,0,65,0,0),(66,'제목66','내용66','2023-11-23 03:09:34',0,NULL,NULL,0,0,66,0,0),(67,'제목67','내용67','2023-11-23 03:09:34',0,NULL,NULL,0,0,67,0,0),(68,'제목68','내용68','2023-11-23 03:09:34',0,NULL,NULL,0,0,68,0,0),(69,'제목69','내용69','2023-11-23 03:09:34',0,NULL,NULL,0,0,69,0,0),(70,'제목70','내용70','2023-11-23 03:09:34',0,NULL,NULL,0,0,70,0,0),(71,'제목71','내용71','2023-11-23 03:09:34',0,NULL,NULL,0,0,71,0,0),(72,'제목72','내용72','2023-11-23 03:09:34',0,NULL,NULL,0,0,72,0,0),(73,'제목73','내용73','2023-11-23 03:09:34',0,NULL,NULL,0,0,73,0,0),(74,'제목74','내용74','2023-11-23 03:09:34',0,NULL,NULL,0,0,74,0,0),(75,'제목75','내용75','2023-11-23 03:09:34',0,NULL,NULL,0,0,75,0,0),(76,'제목76','내용76','2023-11-23 03:09:34',0,NULL,NULL,0,0,76,0,0),(77,'제목77','내용77','2023-11-23 03:09:34',0,NULL,NULL,0,0,77,0,0),(78,'제목78','내용78','2023-11-23 03:09:34',0,NULL,NULL,0,0,78,0,0),(79,'제목79','내용79','2023-11-23 03:09:34',0,NULL,NULL,0,0,79,0,0),(80,'제목80','내용80','2023-11-23 03:09:34',0,NULL,NULL,0,0,80,0,0),(81,'제목81','내용81','2023-11-23 03:09:34',0,NULL,NULL,0,0,81,0,0),(82,'제목82','내용82','2023-11-23 03:09:34',0,NULL,NULL,0,0,82,0,0),(83,'제목83','내용83','2023-11-23 03:09:34',0,NULL,NULL,0,0,83,0,0),(84,'제목84','내용84','2023-11-23 03:09:34',0,NULL,NULL,0,0,84,0,0),(85,'제목85','내용85','2023-11-23 03:09:34',0,NULL,NULL,0,0,85,0,0),(86,'제목86','내용86','2023-11-23 03:09:34',0,NULL,NULL,0,0,86,0,0),(87,'제목87','내용87','2023-11-23 03:09:34',0,NULL,NULL,0,0,87,0,0),(88,'제목88','내용88','2023-11-23 03:09:34',0,NULL,NULL,0,0,88,0,0),(89,'제목89','내용89','2023-11-23 03:09:34',0,NULL,NULL,0,0,89,0,0),(90,'제목90','내용90','2023-11-23 03:09:34',0,NULL,NULL,0,0,90,0,0),(91,'제목91','내용91','2023-11-23 03:09:34',0,NULL,NULL,0,0,91,0,0),(92,'제목92','내용92','2023-11-23 03:09:34',0,NULL,NULL,0,0,92,0,0),(93,'제목93','내용93','2023-11-23 03:09:35',0,NULL,NULL,0,0,93,0,0),(94,'제목94','내용94','2023-11-23 03:09:35',0,NULL,NULL,0,0,94,0,0),(95,'제목95','내용95','2023-11-23 03:09:35',0,NULL,NULL,0,0,95,0,0),(96,'제목96','내용96','2023-11-23 03:09:35',0,NULL,NULL,0,0,96,0,0),(97,'제목97','내용97','2023-11-23 03:09:35',0,NULL,NULL,0,0,97,0,0),(98,'제목98','내용98','2023-11-23 03:09:35',0,NULL,NULL,0,0,98,0,0),(99,'제목99','내용99','2023-11-23 03:09:35',0,NULL,NULL,0,0,99,0,0),(100,'제목100','내용100','2023-11-23 03:09:35',1,NULL,NULL,0,0,100,0,0),(101,'제목101','내용101','2023-11-23 03:09:35',2,NULL,NULL,0,0,101,0,0),(103,'질문1','<p>질문1&nbsp;</p>','2023-11-23 23:25:52',1,'스크린샷 2023-11-10 091043.png','1700781952833.png',0,3,103,0,0),(104,'질문2','<p><img title=\"스크린샷 2023-10-04 163900.png\" src=\"http://localhost:8090/project/upload/editor/1700782005433_275.png\" alt=\"\"><br style=\"clear:both;\">&nbsp;</p>','2023-11-23 23:26:46',1,NULL,NULL,0,3,104,0,0),(105,'101의 답변','<p>&nbsp;</p>','2023-11-23 23:27:09',0,NULL,NULL,0,3,101,1,1),(106,'ㅅㄷㄴㅅ','<p>안녕하세요</p><p><b><span style=\"background-color: rgb(119, 119, 119); color: rgb(255, 0, 0);\">안녕</span></b></p><p>안녕</p><p><img title=\"스크린샷 2023-10-04 163900.png\" src=\"http://localhost:8090/project/upload/editor/1700788184310_90.png\" alt=\"\"><br style=\"clear:both;\">&nbsp;</p>','2024-02-05 01:53:45',15,'스크린샷 2023-11-10 091043.png','1700789226621.png',0,3,106,0,0),(108,'답변1','<p>&nbsp;</p>','2023-11-24 01:31:15',0,NULL,NULL,0,3,106,3,1),(109,'답변2','<p>&nbsp;</p>','2023-11-24 01:32:02',3,NULL,NULL,0,3,106,1,1),(110,'답변2의 답변','<p>&nbsp;</p>','2023-11-24 01:32:20',0,NULL,NULL,0,3,106,2,2),(115,'제목 테스트','내용 테스트','2024-02-01 06:57:33',0,NULL,NULL,0,NULL,115,0,0),(116,'제목 테스트','내용 테스트','2024-02-01 07:16:58',0,NULL,NULL,0,NULL,116,0,0),(117,'제목 테스트','내용 테스트','2024-02-05 01:56:46',1,NULL,NULL,0,3,117,0,0),(118,'ㅇㅇㅇ','ㄴㄴㄴ','2024-02-01 07:36:10',0,NULL,NULL,0,3,118,0,0),(119,NULL,NULL,'2024-02-01 07:38:41',0,NULL,NULL,0,3,119,0,0),(120,'ㄴㄴ','ㄷㄷ','2024-02-02 06:40:10',2,NULL,NULL,0,3,120,0,0),(121,'ㄹㄹㄹ234','ㄹㄹㄹ234','2024-02-02 08:27:03',85,'조별 미니 프로젝트.txt','1706857188285.txt',0,3,121,0,0),(128,'121의 답변','121의 답변','2024-02-02 08:12:02',2,NULL,NULL,0,3,121,3,1),(129,'121의 답변2','121의 답변2','2024-02-02 08:09:16',0,NULL,NULL,0,3,121,2,1),(130,'121의 답변3','121의 답변3','2024-02-02 08:26:57',1,NULL,NULL,0,3,121,4,2),(131,'123의 답변!!','123의 답변!!','2024-02-02 08:26:53',3,NULL,NULL,0,3,121,1,1),(132,'안녕하세요',NULL,'2024-02-27 11:19:42',29,'디자인 패턴 (design pattern).txt','1706862444249.txt',0,3,132,0,0),(133,'답변1','','2024-02-02 08:28:23',2,NULL,NULL,0,3,132,3,1),(134,'답변2','','2024-02-02 08:28:25',5,NULL,NULL,0,3,132,1,1),(135,'답변2의 답변','답변2의 답변','2024-02-27 06:22:28',3,NULL,NULL,0,3,132,2,2);
/*!40000 ALTER TABLE `reply` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user` (
  `no` int NOT NULL AUTO_INCREMENT,
  `email` varchar(45) NOT NULL,
  `pwd` varchar(255) NOT NULL,
  `name` varchar(45) NOT NULL,
  `gender` int DEFAULT NULL,
  `birthday` char(10) DEFAULT NULL,
  `hp` varchar(45) DEFAULT NULL,
  `registdate` timestamp NULL DEFAULT NULL,
  `zipcode` varchar(6) DEFAULT NULL,
  `addr1` varchar(45) DEFAULT NULL,
  `addr2` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`no`),
  UNIQUE KEY `email_UNIQUE` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user`
--

LOCK TABLES `user` WRITE;
/*!40000 ALTER TABLE `user` DISABLE KEYS */;
INSERT INTO `user` VALUES (1,'hong@gmail.com','f31e719f12c10e20f0bda09ebe931618','홍길동',0,'2023-11-20','010-1234-5678','2023-11-20 02:33:33',NULL,NULL,NULL),(3,'park@gmail.com','506e0c433d8cc9ef13e841bdbb2366eb','박길동',1,NULL,'010-1234-5678','2023-11-21 02:31:36',NULL,NULL,NULL),(4,'choi@gmail.com','2a98932fe9057a7be25e5b78c632d980','최길동',1,NULL,'010-1234-5678','2023-11-21 02:34:35',NULL,NULL,NULL),(5,'kim@gmail.com','16d7a4fca7442dda3ad93c9a726597e4','김길동2',1,NULL,'010-1234-5678','2023-11-21 02:40:14','62048','광주 서구 월드컵남로 28','1234');
/*!40000 ALTER TABLE `user` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-02-23  4:31:28
