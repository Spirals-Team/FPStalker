SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;


CREATE TABLE `extensionDataSchem` (
  `counter` int(11) NOT NULL,
  `id` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `addressHttp` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `creationDate` datetime NOT NULL,
  `updateDate` datetime DEFAULT NULL,
  `endDate` datetime DEFAULT NULL,
  `userAgentHttp` varchar(300) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `acceptHttp` varchar(300) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `hostHttp` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `connectionHttp` varchar(100) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `encodingHttp` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `languageHttp` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `orderHttp` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `pluginsJS` text CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `platformJS` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `cookiesJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `dntJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `timezoneJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `resolutionJS` varchar(20) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `localJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `sessionJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `IEDataJS` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `canvasJS` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `webGLJs` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `fontsFlash` mediumtext CHARACTER SET utf8 COLLATE utf8_unicode_ci,
  `resolutionFlash` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `languageFlash` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `platformFlash` varchar(50) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `adBlock` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `vendorWebGLJS` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `rendererWebGLJS` varchar(200) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `octaneScore` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `sunspiderTime` varchar(10) CHARACTER SET utf8 COLLATE utf8_unicode_ci DEFAULT NULL,
  `pluginsJSHashed` varchar(40) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `canvasJSHashed` varchar(40) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `webGLJsHashed` varchar(40) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `fontsFlashHashed` varchar(40) CHARACTER SET utf8 COLLATE utf8_unicode_ci NOT NULL,
  `osDetailed` varchar(80) NOT NULL,
  `browserDetailed` varchar(100) NOT NULL,
  `browserVersion` varchar(30) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

ALTER TABLE `extensionDataSchem`
  ADD PRIMARY KEY (`counter`);

ALTER TABLE `extensionDataSchem`
  MODIFY `counter` int(11) NOT NULL AUTO_INCREMENT;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
