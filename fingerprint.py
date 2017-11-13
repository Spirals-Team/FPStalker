from ua_parser import user_agent_parser
import re
import math as mt
import hashlib

class Fingerprint():

    ID = "id"
    COUNTER = "counter"
    CREATION_TIME = "creationDate"
    END_TIME = "endDate"

    # HTTP attributes
    ACCEPT_HTTP = "acceptHttp"
    LANGUAGE_HTTP = "languageHttp"
    USER_AGENT_HTTP = "userAgentHttp"
    ORDER_HTTP = "orderHttp"
    ADDRESS_HTTP = "addressHttp"
    CONNECTION_HTTP = "connectionHttp"
    ENCODING_HTTP = "encodingHttp"
    HOST_HTTP = "hostHttp"

    BROWSER_FAMILY = "browserFamily"
    MINOR_BROWSER_VERSION = "minorBrowserVersion"
    MAJOR_BROWSER_VERSION = "majorBrowserVersion"
    GLOBAL_BROWSER_VERSION = "globalBrowserVersion"
    OS = "os"

    IS_CHROME = "isChrome"
    IS_FIREFOX = "isFirefox"
    IS_SAFARI = "isSafari"
    IS_IE = "isIE"
    IS_OPERA = "isOpera"
    IS_OTHER_BROWSER = "isOtherBrowser"

    IS_WINDOWS_DESKTOP = "isWindowsDesktop"
    IS_MAC_DESKTOP = "isMacDesktop"
    IS_LINUX_DESKTOP = "isLinuxDesktop"
    IS_WINDOWS_MOBILE = "isWindowsMobile"
    IS_MAC_MOBILE = "isMacMobile"
    IS_ANDROID = "isAndroid"
    IS_OTHER_OS = "isOtherOs"

    # Javascript attributes
    COOKIES_JS = "cookiesJS"
    RESOLUTION_JS = "resolutionJS"
    TIMEZONE_JS = "timezoneJS"
    PLUGINS_JS = "pluginsJS"
    PLUGINS_JS_HASHED = "pluginsJSHashed"
    SESSION_JS = "sessionJS"
    DNT_JS = "dntJS"
    IE_DATA_JS = "IEDataJS"
    CANVAS_JS_HASHED = "canvasJSHashed"
    LOCAL_JS = "localJS"
    PLATFORM_JS = "platformJS"
    AD_BLOCK = "adBlock"
    RENDERER = "rendererWebGLJS"
    VENDOR = "vendorWebGLJS"

    NB_PLUGINS = "nbPlugins"
    PLATFORM_INCONSISTENCY = "platformInconsistency"

    # Flash attributes
    PLATFORM_FLASH = "platformFlash"
    FONTS_FLASH = "fontsFlash"
    FONTS_FLASH_HASHED = "fontsFlashHashed"
    LANGUAGE_FLASH = "languageFlash"
    RESOLUTION_FLASH = "resolutionFlash"

    NB_FONTS = "nbFonts"
    LANGUAGE_INCONSISTENCY = "languageInconsistency"

    MOST_USED_PLUGINS = set(["Shockwave Flash", "Chrome PDF Viewer",
                             "QuickTime Plug-in ", "Native Client",
                             "Widevine Content Decryption Module",
                             "Microsoft Office ", "Adobe Acrobat",
                             "Silverlight Plug-In", "Google Update",
                             "JavaTM Platform SE ",
                             "Java Deployment Toolkit ",
                             "Chrome Remote Desktop Viewer",
                             "Intel", "VLC Web Plugin", "NVIDIA ",
                             "iTunes Application Detector",
                             "Default Browser Helper",
                             "Google Talk Plugin",
                             "Google Talk Plugin Video Renderer",
                             "Java Applet Plug-in",
                             "Shockwave for Director",
                             "AdobeAAMDetect",
                             "Unity Player",
                             "Google Earth Plugin",
                             "SharePoint Browser Plug-in",
                             "Citrix Online Web Deployment Plugin ",
                             "Chromium PDF Viewer",
                             "DivX", "Windows Media Player Plug-in ",
                             "VLC Multimedia Plugin compatible Videos ",
                             "Photo Gallery",
                             "IcedTea-Web Plugin using IcedTea-Web ",
                             "Microsoft",
                             "ActiveTouch General Plugin Container",
                             "WindowsMediaPlayer ",
                             "Flash ",
                             "Adobe Acrobat NPAPI Plug-in Version ",
                             "WebKit built-in PDF",
                             "Picasa",
                             "Gnome Shell Integration"])
    MOST_USED_BROWSERS = set(["Firefox", "Chrome"])
    MOST_USED_OS = set(["Windows 7", "Mac OS X",
                        "Windows 10", "Windows 8.1", "Linux"])

    INFO_ATTRIBUTES = [ID, COUNTER, CREATION_TIME, END_TIME]
    INFO_WITHOUT_TIME = [ID, COUNTER]

    HTTP_ATTRIBUTES = [ACCEPT_HTTP, LANGUAGE_HTTP, USER_AGENT_HTTP,
                       ADDRESS_HTTP, CONNECTION_HTTP,
                       ENCODING_HTTP]

    HTTP_WITHOUT_IP = [ACCEPT_HTTP, LANGUAGE_HTTP, USER_AGENT_HTTP,
                       ORDER_HTTP, CONNECTION_HTTP,
                       ENCODING_HTTP, HOST_HTTP, BROWSER_FAMILY,
                       MINOR_BROWSER_VERSION, MAJOR_BROWSER_VERSION, OS]

    JAVASCRIPT_ATTRIBUTES = [COOKIES_JS, RESOLUTION_JS, TIMEZONE_JS,
                             PLUGINS_JS, SESSION_JS, DNT_JS, IE_DATA_JS,
                             CANVAS_JS_HASHED, LOCAL_JS, PLATFORM_JS,
                             NB_PLUGINS, PLATFORM_INCONSISTENCY,
                             PLUGINS_JS_HASHED, VENDOR, RENDERER]

    FLASH_ATTRIBUTES = [PLATFORM_FLASH, FONTS_FLASH, LANGUAGE_FLASH, FONTS_FLASH_HASHED,
                        RESOLUTION_FLASH, NB_FONTS, LANGUAGE_INCONSISTENCY]

    MYSQL_ATTRIBUTES = set([COUNTER, ID, CREATION_TIME, END_TIME, ADDRESS_HTTP,
                            USER_AGENT_HTTP, ACCEPT_HTTP, HOST_HTTP,
                            CONNECTION_HTTP, ENCODING_HTTP, LANGUAGE_HTTP,
                            ORDER_HTTP, PLUGINS_JS, PLATFORM_JS, COOKIES_JS,
                            DNT_JS, TIMEZONE_JS, RESOLUTION_JS, LOCAL_JS,
                            SESSION_JS, IE_DATA_JS, CANVAS_JS_HASHED,
                            FONTS_FLASH, RESOLUTION_FLASH, LANGUAGE_FLASH,
                            PLATFORM_FLASH, AD_BLOCK])

    def __init__(self, list_attributes, val_attributes):
        self.val_attributes = dict()
        for attribute in list_attributes:
            try:
                self.val_attributes[attribute] = val_attributes[attribute]
            except:
                # exception happens when the value of the attribute has to
                # be determined dynamically (ie nb plugins, browser version)
                self.val_attributes[attribute] = None

        # we reorder resolution when necessary (usefull for mobile users)
        if Fingerprint.RESOLUTION_JS in list_attributes:
            if self.val_attributes[Fingerprint.RESOLUTION_JS] != "no JS":
                split_res = self.val_attributes[Fingerprint.RESOLUTION_JS].split("x")
                if len(split_res) > 1 and split_res[1] > split_res[0]:
                    self.val_attributes[Fingerprint.RESOLUTION_JS] = split_res[1] +\
                        "x"+ split_res[0] + "x"+ split_res[2]

        if Fingerprint.PLUGINS_JS in list_attributes:
            plugins = self.getPlugins()
            self.exoticPlugins = set()
            for plugin in plugins:
                if not Fingerprint.MOST_USED_PLUGINS.__contains__(plugin):
                    self.exoticPlugins.add(plugin)

        if Fingerprint.ORDER_HTTP in list_attributes:
            orders = self.val_attributes[Fingerprint.ORDER_HTTP].split(" ")
            orders.sort()
            self.val_attributes[Fingerprint.ORDER_HTTP] = " ".join(orders)

        if Fingerprint.USER_AGENT_HTTP in list_attributes:
            parsedUa = user_agent_parser.Parse(val_attributes[Fingerprint.USER_AGENT_HTTP])
            self.val_attributes[Fingerprint.BROWSER_FAMILY] = parsedUa["user_agent"]["family"]
            self.val_attributes[Fingerprint.MINOR_BROWSER_VERSION] = parsedUa["user_agent"]["minor"]
            self.val_attributes[Fingerprint.MAJOR_BROWSER_VERSION] = parsedUa["user_agent"]["major"]
            try:
                self.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] = self.val_attributes[Fingerprint.MAJOR_BROWSER_VERSION] + \
                                                                      self.val_attributes[Fingerprint.MINOR_BROWSER_VERSION]
            except:
                self.val_attributes[Fingerprint.GLOBAL_BROWSER_VERSION] = "zzzzzz"

            self.val_attributes[Fingerprint.OS] = parsedUa["os"]["family"]

            self.isExoticOS = Fingerprint.MOST_USED_OS.__contains__(self.val_attributes[Fingerprint.OS])
            self.isExoticBrowser = Fingerprint.MOST_USED_BROWSERS.__contains__(self.val_attributes[Fingerprint.BROWSER_FAMILY])

        if Fingerprint.PLATFORM_INCONSISTENCY in list_attributes and self.hasJsActivated():
            self.val_attributes[Fingerprint.PLATFORM_INCONSISTENCY] = self.hasPlatformInconsistency()
            # pass

        # compute hash of subparts of fingerprint for optimisation
        # os, platform, browser
        self.constant_hash = hashlib.md5(str.encode(self.val_attributes[Fingerprint.OS] + \
                                                    self.val_attributes[Fingerprint.PLATFORM_JS] +\
                                                    self.val_attributes[Fingerprint.BROWSER_FAMILY]
                                                   )
                                        ).hexdigest()

        fp_string = [str(self.val_attributes[att]) for att in self.JAVASCRIPT_ATTRIBUTES]
        fp_string += self.val_attributes[Fingerprint.USER_AGENT_HTTP]
        fp_string += self.val_attributes[Fingerprint.LANGUAGE_HTTP]
        fp_string += self.val_attributes[Fingerprint.ACCEPT_HTTP]
        fp_string += self.val_attributes[Fingerprint.ENCODING_HTTP]
        fp_string += self.val_attributes[Fingerprint.FONTS_FLASH]
        self.hash = hashlib.md5(str.encode("".join(fp_string))).hexdigest()

    def hasJsActivated(self):
        try:
            return self.val_attributes[Fingerprint.TIMEZONE_JS] != "no JS"
        except:
            return False

    def hasFlashActivated(self):
        try:
            return self.val_attributes[Fingerprint.FONTS_FLASH] != "Flash detected but not activated (click-to-play)" and \
                self.val_attributes[Fingerprint.FONTS_FLASH] != "Flash not detected" and \
                self.val_attributes[Fingerprint.FONTS_FLASH] != "Flash detected but blocked by an extension"
        except:
            return False

    def getStartTime(self):
        return self.val_attributes[Fingerprint.CREATION_TIME]

    def getEndTime(self):
        return self.val_attributes[Fingerprint.END_TIME]

    def getTimezone(self):
        return self.val_attributes[Fingerprint.TIMEZONE_JS]

    def getUserAgent(self):
        return self.val_attributes[Fingerprint.USER_AGENT_HTTP]

    def getFonts(self):
        if self.hasFlashActivated():
            return self.val_attributes[Fingerprint.FONTS_FLASH].split("_")
        else:
            return []

    def getNumberFonts(self):
        return len(self.getFonts())

    def getPlugins(self):
        if self.hasJsActivated():
            return re.findall("Plugin [0-9]+: ([a-zA-Z -.]+)", self.val_attributes[Fingerprint.PLUGINS_JS])
        else:
            return []

    def getNumberOfPlugins(self):
        return self.val_attributes[Fingerprint.NB_PLUGINS]

    def getBrowser(self):
        return self.val_attributes[Fingerprint.BROWSER_FAMILY]

    def getOs(self):
        return self.val_attributes[Fingerprint.OS]

    def hasLanguageInconsistency(self):
        if self.hasFlashActivated():
            try:
                langHttp = self.val_attributes[Fingerprint.LANGUAGE_HTTP][0:2].lower()
                langFlash = self.val_attributes[Fingerprint.LANGUAGE_FLASH][0:2].lower()
                return not (langHttp == langFlash)
            except:
                return True
        else:
            raise ValueError("Flash is not activated")

    def hasChromeInconsistency(self):
        return self.val_attributes[Fingerprint.BROWSER_FAMILY] != "Chrome" and "Chrome PDF Viewer" in self.val_attributes[Fingerprint.PLUGINS_JS]

    def hasPlatformInconsistency(self):
        if self.hasJsActivated():
            try:
                plat = ""
                platUa = self.getOs()[0:3].lower()
                if self.hasFlashActivated():
                    platFlash = self.val_attributes[Fingerprint.PLATFORM_FLASH][0:3].lower()
                    plat = platFlash
                else:
                    platJs = self.val_attributes[Fingerprint.PLATFORM_JS][0:3].lower()
                    plat = platJs
                    if (platUa == "lin" or platUa=="ubu" or platUa =="ios" or platUa=="and") and self.val_attributes[Fingerprint.PLUGINS_JS].find(".dll") > -1:
                        return True
                    if platUa.startswith("ip") and self.val_attributes[Fingerprint.PLUGINS_JS].lower().find("flash") > -1:
                        return True
                    if (platUa == "win" or platUa == "mac" or platUa == "ios") and self.val_attributes[Fingerprint.PLUGINS_JS].find(".so") > -1:
                        return True
                    if (platUa == "ubu" or platUa == "win" or platUa == "lin") and self.val_attributes[Fingerprint.PLUGINS_JS].find(".plugin") > -1:
                        return True
                incons = not(plat == platUa)
                if plat == "lin" and platUa == "and":
                    incons = False
                elif plat == "lin" and platUa == "ubu":
                    incons = False
                elif plat == "x64" and platUa == "win":
                    incons = False
                elif plat == "ipa" and platUa == "ios":
                    incons = False
                elif plat == "iph" and platUa == "ios":
                    incons = False
                elif plat == "" and platUa == "":
                    incons = True

                elif plat == "lin" and platUa == "and":
                    incons = False
                elif plat == "lin" and platUa == "ubu":
                    incons = False
                elif plat == "x64" and platUa == "win":
                    incons = False
                elif plat == "ipa" and platUa == "ios":
                    incons = False
                elif plat == "iph" and platUa == "ios":
                    incons = False
                elif plat == "ipo" and platUa == "ios":
                    incons = False
                elif self.getOs() == "Windows Phone" and plat == "arm":
                    incons = False
                elif plat == "arm" and self.val_attributes[Fingerprint.USER_AGENT_HTTP].find("SIM") > -1:
                    incons = False
                elif platUa == "chr" and plat == "lin":
                    incons = False
                elif self.val_attributes[Fingerprint.USER_AGENT_HTTP].find("Touch") > -1 and plat == "arm":
                    incons = False
                elif platUa == "oth":
                    incons = False
                elif plat == "" and platUa == "":
                    incons = True

                return incons
            except:
                return True
        else:
            raise ValueError("Javascript is not activated")

    def hasFlashBlockedByExtension(self):
        return self.val_attributes[Fingerprint.PLATFORM_FLASH] == "Flash detected but blocked by an extension"

    def getTimeDifference(self, fp):
        try:
            diff = self.getStartTime() - fp.getStartTime()
            return mt.fabs(diff.days + diff.seconds / (3600.0 * 24))
        except:  # for the case where we try to link blink's fingerprints
            return self.getCounter() - fp.getCounter()

    def hasSameOs(self, fp):
        return self.getOs() == fp.getOs()

    def hasSameBrowser(self, fp):
        return self.getBrowser() == fp.getBrowser()

    def hasSameTimezone(self, fp):
        return self.val_attributes[Fingerprint.TIMEZONE_JS] == fp.val_attributes[Fingerprint.TIMEZONE_JS]

    def hasSameResolution(self, fp):
        return self.val_attributes[Fingerprint.RESOLUTION_JS] == fp.val_attributes[Fingerprint.RESOLUTION_JS]

    def hasSameAdblock(self, fp):
        return self.val_attributes[Fingerprint.AD_BLOCK] == fp.val_attributes[Fingerprint.AD_BLOCK]

    def hasSameHttpLanguages(self, fp):
        return self.val_attributes[Fingerprint.LANGUAGE_HTTP] == fp.val_attributes[Fingerprint.LANGUAGE_HTTP]

    def hasSameAcceptHttp(self, fp):
        return self.val_attributes[Fingerprint.ACCEPT_HTTP] == fp.val_attributes[Fingerprint.ACCEPT_HTTP]

    def hasSameEncodingHttp(self, fp):
        return self.val_attributes[Fingerprint.ENCODING_HTTP] == fp.val_attributes[Fingerprint.ENCODING_HTTP]

    def hasSameUserAgentHttp(self, fp):
        return self.val_attributes[Fingerprint.USER_AGENT_HTTP] == fp.val_attributes[Fingerprint.USER_AGENT_HTTP]

    def hasSameOrderHttp(self, fp):
        return self.val_attributes[Fingerprint.ORDER_HTTP] == fp.val_attributes[Fingerprint.ORDER_HTTP]

    def hasSameConnectionHttp(self, fp):
        return self.val_attributes[Fingerprint.CONNECTION_HTTP] == fp.val_attributes[Fingerprint.CONNECTION_HTTP]

    def hasSamePlugins(self, fp):
        pluginsSet1 = set(self.getPlugins())
        pluginsSet2 = set(fp.getPlugins())
        return pluginsSet1 == pluginsSet2

    def hasSamePluginString(self, fp):
        return self.val_attributes[Fingerprint.PLUGINS_JS] == fp.val_attributes[Fingerprint.PLUGINS_JS]

    def hasSameNbPlugins(self, fp):
        return self.val_attributes[Fingerprint.NB_PLUGINS] == fp.val_attributes[Fingerprint.NB_PLUGINS]

    def hasSameFonts(self, fp):
        return self.val_attributes[Fingerprint.FONTS_FLASH_HASHED] == fp.val_attributes[Fingerprint.FONTS_FLASH_HASHED]

    def hasSamePlatformFlash(self, fp):
        return self.val_attributes[Fingerprint.PLATFORM_FLASH] == fp.val_attributes[Fingerprint.PLATFORM_FLASH]

    def hasSameLanguageFlash(self, fp):
        return self.val_attributes[Fingerprint.LANGUAGE_FLASH] == fp.val_attributes[Fingerprint.LANGUAGE_FLASH]

    def hasSameResolutionFlash(self, fp):
        return self.val_attributes[Fingerprint.RESOLUTION_FLASH] == fp.val_attributes[Fingerprint.RESOLUTION_FLASH]

    def hasSameNbFonts(self, fp):
        return self.val_attributes[Fingerprint.NB_FONTS] == fp.val_attributes[Fingerprint.NB_FONTS]

    def hasSameCanvasJsHashed(self, fp):
        return self.val_attributes[Fingerprint.CANVAS_JS_HASHED] == fp.val_attributes[Fingerprint.CANVAS_JS_HASHED]

    def hasSamePlatformJs(self, fp):
        return self.val_attributes[Fingerprint.PLATFORM_JS] == fp.val_attributes[Fingerprint.PLATFORM_JS]

    def hasSameSessionJs(self, fp):
        return self.val_attributes[Fingerprint.SESSION_JS] == fp.val_attributes[Fingerprint.SESSION_JS]

    def hasSameAddressHttp(self, fp):
        return self.val_attributes[Fingerprint.ADDRESS_HTTP] == fp.val_attributes[Fingerprint.ADDRESS_HTTP]

    def hasSameDnt(self, fp):
        return self.val_attributes[Fingerprint.DNT_JS] == fp.val_attributes[Fingerprint.DNT_JS]

    def hasSameCookie(self, fp):
        return self.val_attributes[Fingerprint.COOKIES_JS] == fp.val_attributes[Fingerprint.COOKIES_JS]

    def hasSameLocalJs(self, fp):
        return self.val_attributes[Fingerprint.LOCAL_JS] == fp.val_attributes[Fingerprint.LOCAL_JS]

    def hasSamePlatformInconsistency(self, fp):
        if self.val_attributes[Fingerprint.PLATFORM_INCONSISTENCY] and fp.val_attributes[Fingerprint.PLATFORM_INCONSISTENCY]:
            return "0"
        elif self.val_attributes[Fingerprint.PLATFORM_INCONSISTENCY] or fp.val_attributes[Fingerprint.PLATFORM_INCONSISTENCY]:
            return "1"
        else:
            return "2"

    # Compare the current fingerprint with another one (fp)
    # Returns True if the current fingerprint has a highest (or equal) version of browser
    def hasHighestBrowserMajorVersion(self, fp):
        if self.getCounter() > fp.getCounter():
            mostRecent = self
            oldest = fp
        else:
            mostRecent = fp
            oldest = self

        try:
            return mostRecent.val_attributes[Fingerprint.MAJOR_BROWSER_VERSION] >= oldest.val_attributes[Fingerprint.MAJOR_BROWSER_VERSION]
        except:
            return True

    def hasHighestBrowserMinorVersion(self, fp):
        if self.getCounter() > fp.getCounter():
            mostRecent = self
            oldest = fp
        else:
            mostRecent = fp
            oldest = self

        try:
            return mostRecent.val_attributes[Fingerprint.MINOR_BROWSER_VERSION] >= oldest.val_attributes[
                Fingerprint.MINOR_BROWSER_VERSION]
        except:
            return True

    # Returns True if the plugins of the current fingerprint are a subset of another fingerprint fp or the opposite
    # Else, it returns False
    def arePluginsSubset(self, fp):
        pluginsSet1 = set(self.getPlugins())
        pluginsSet2 = set(fp.getPlugins())
        return (pluginsSet1.issubset(pluginsSet2) or pluginsSet2.issubset(pluginsSet1))

    def getNumberDifferentPlugins(self, fp):
        pluginsSet1 = set(self.getPlugins())
        pluginsSet2 = set(fp.getPlugins())
        return max(self.getNumberOfPlugins(), fp.getNumberOfPlugins()) - len(pluginsSet1.intersection(pluginsSet2))

    def getNumberExoticPluginsCommons(self, fp):
        return len(self.exoticPlugins.intersection(fp.exoticPlugins))

    # Returns True if the fonts of the current fingerprint are a subset of another fingerprint fp or the opposite
    # Else, it returns False
    def areFontsSubset(self, fp):
        fontsSet1 = set(self.getFonts())
        fontsSet2 = set(fp.getFonts())
        return (fontsSet1.issubset(fontsSet2) or fontsSet2.issubset(fontsSet1))

    # return True if 2 fingeprints belong to the same user (based on the id criteria)
    def belongToSameUser(self, fp):
        return self.val_attributes[Fingerprint.ID] == fp.val_attributes[Fingerprint.ID]

    def getId(self):
        return self.val_attributes[Fingerprint.ID]

    def getCounter(self):
        return self.val_attributes[Fingerprint.COUNTER]
