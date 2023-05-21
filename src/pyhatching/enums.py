"""Enums of static Hatching Triage API objects."""

from enum import Enum


class CompleteStatuses(Enum):
    """The "terminal" statuses of Hatching Triage."""

    REPORTED: str = "reported"
    FAILED: str = "failed"


class SubmssionsRequestNetDefaults(Enum):
    """The network default options for a sample submission."""

    INTERNET: str = "internet"
    DROP: str = "drop"
    TOR: str = "tor"


class SubmissionKinds(Enum):
    """The valid kinds of submissions."""

    FILE: str = "file"
    URL: str = "url"
    FETCH: str = "fetch"


class SampleKinds(Enum):
    """The valid kinds of submissions."""

    FILE: str = "file"
    URL: str = "url"


class SubmissionStatuses(Enum):
    """The status of a submission."""

    RUNNING: str = "running"
    PENDING: str = "pending"
    STATIC_ANALYSIS: str = "static_analysis"
    SCHEDULED: str = "scheduled"
    PROCESSING: str = "processing"
    REPORTED: str = "reported"
    FAILED: str = "failed"


class ErrorNames(Enum):
    """Names of Hatching Triage errors."""

    BAD_REQUEST: str = "BAD_REQUEST"
    INVALID: str = "INVALID"
    UNAUTHORIZED: str = "UNAUTHORIZED"
    NOT_FOUND: str = "NOT_FOUND"
    METHOD_NOT_ALLOWED: str = "METHOD_NOT_ALLOWED"
    INTERNAL: str = "INTERNAL"
    ERRONEOUS_FILENAME: str = "ERRONEOUS_FILENAME"
    COMPILE_ERROR: str = "COMPILE_ERROR"
    PROFILE_ALREADY_EXISTS: str = "PROFILE_ALREADY_EXISTS"
    PROFILE_NOT_SETTABLE: str = "PROFILE_NOT_SETTABLE"
    REPORT_NOT_AVAILABLE: str = "REPORT_NOT_AVAILABLE"


class ErrorDesc(Enum):
    """Descriptions for each Hatching Triage error."""

    BAD_REQUEST: str = "An error occurred while decoding the request."
    INVALID: str = "One or more required fields have a value that is not allowed."
    UNAUTHORIZED: str = "Missing or invalid credentials."
    NOT_FOUND: str = "Object not found or non-existing endpoint."
    METHOD_NOT_ALLOWED: str = "Method not allowed for endpoint."
    INTERNAL: str = "The request was valid, but the server could not process it."


class ProfileNetworkOptions(Enum):
    """Available network options for sandbox analysis.
    
    Parameters
    ----------
    "": The system default
    "drop": Disable networking.
    "internet": Allow connections to the internet.
    "tor": Route internet through the Tor network.
    "sim200": InetSim-like functionality with HTTP 200 responses.
    "sim404": InetSim-like functionality with HTTP 404 responses.
    "simnx": InetSim-like functionality with DNS NXDOMAIN responses.
    """

    DEFAULT: str = ""
    DROP: str = "drop"
    INTERNET: str = "internet"
    TOR: str = "tor"
    SIM200: str = "sim200"
    SIM404: str = "sim404"
    SIMNX: str = "simnx"


class HashPrefixes(Enum):
    MD5: str = "md5"
    SHA1: str = "sha1"
    SHA2: str = "sha256"
    SHA5: str = "sha512"


class AvailableTags(Enum):
    """All tags supported by Hatching Triage."""

    ADWARE: str = "adware"
    ANTIVM: str = "antivm"
    APT: str = "apt"
    BACKDOOR: str = "backdoor"
    BANKER: str = "banker"
    BOOTKIT: str = "bootkit"
    BOTNET: str = "botnet"
    DISCOVERY: str = "discovery"
    DOWNLOADER: str = "downloader"
    DROPPER: str = "dropper"
    EVASION: str = "evasion"
    EXPLOIT: str = "exploit"
    ICS: str = "ics"
    INFOSTEALER: str = "infostealer"
    KEYLOGGER: str = "keylogger"
    LOADER: str = "loader"
    MALDOC: str = "maldoc"
    MINER: str = "miner"
    OVERLAY: str = "overlay"
    PERSISTENCE: str = "persistence"
    RANSOMWARE: str = "ransomware"
    RAT: str = "rat"
    ROOTKIT: str = "rootkit"
    SPYWARE: str = "spyware"
    STEALER: str = "stealer"
    TROJAN: str = "trojan"
    WIPER: str = "wiper"
    WORM: str = "worm"


class AvailableFams(Enum):
    """All malware families reported on by Hatching Triage."""

    AGENTTESLA: str = "agenttesla"
    ASYNCRAT: str = "asyncrat"
    AZORULT: str = "azorult"
    BAZARBACKDOOR: str = "bazarbackdoor"
    COBALTSTRIKE: str = "cobaltstrike"
    DARKCOMET: str = "darkcomet"
    DRIDEX: str = "dridex"
    EMOTET: str = "emotet"
    FORMBOOK: str = "formbook"
    GOZI_IFSB: str = "gozi_ifsb"
    HAWKEYE: str = "hawkeye"
    HAWKEYE_REBORN: str = "hawkeye_reborn"
    ICEDID: str = "icedid"
    LOKIBOT: str = "lokibot"
    MASSLOGGER: str = "masslogger"
    MATIEX: str = "matiex"
    METASPLOIT: str = "metasploit"
    MODILOADER: str = "modiloader"
    NANOCORE: str = "nanocore"
    NETWIRE: str = "netwire"
    NJRAT: str = "njrat"
    PONY: str = "pony"
    QAKBOT: str = "qakbot"
    QNODESERVICE: str = "qnodeservice"
    RACCOON: str = "raccoon"
    REMCOS: str = "remcos"
    REVENGERAT: str = "revengerat"
    SMOKELOADER: str = "smokeloader"
    SODINOKIBI: str = "sodinokibi"
    TRICKBOT: str = "trickbot"
    UPATRE: str = "upatre"
    WANNACRY: str = "wannacry"
    YUNSIP: str = "yunsip"
    ZLOADER: str = "zloader"


class AvailableOSes(Enum):
    """Special tags to filter on Operating System."""

    ANDROID: str = "android"
    LINUX: str = "linux"
    MACOS: str = "macos"


class SupportedFileTypes(Enum):
    """An enum of the file types supported by Hatching Triage."""

    # Executables
    DLL: str = "DLL"
    EXE: str = "EXE"
    MSI: str = "MSI"
    # Archives
    _7z: str = "7z"
    ACE: str = "ACE"
    BZ2: str = "BZ2"
    CAB: str = "CAB"
    DAA: str = "DAA"
    EML: str = "EML"
    GZIP: str = "GZIP"
    IMG: str = "IMG"
    ISO: str = "ISO"
    LZ: str = "LZ"
    LZH: str = "LZH"
    MSG: str = "MSG"
    PKZIP: str = "PKZIP"
    RAR: str = "RAR"
    TAR: str = "TAR"
    TNEF: str = "TNEF"
    VBN: str = "VBN"
    VHD: str = "VHD"
    XAR: str = "XAR"
    XZ: str = "XZ"
    ZIP: str = "ZIP"
    # Documents
    CHM: str = "CHM"
    HTA: str = "HTA"
    IQY: str = "IQY"
    OFFICE03: str = "Office 2003"
    OFFICE07: str = "Office 2007+"
    OPENOFFICE: str = "OpenOffice"
    PDF: str = "PDF"
    RTF: str = "RTF"
    SLK: str = "SLK"
    SWF: str = "SWF"
    HTML: str = "HTML"
    # Scripting
    BAT: str = "BAT"
    PS1: str = "PS1"
    JS: str = "JS"
    JSE: str = "JSE"
    VBE: str = "VBE"
    PL: str = "PL"
    VBS: str = "VBS"
    WSF: str = "WSF"
    # macOS
    APP: str = "APP"
    DMG: str = "DMG"
    MACHO: str = "mach-O"
    PKG: str = "PKG"
    SCPT: str = "SCPT"
    # Android
    APK:str = "APK"
    DEX:str = "DEX"
    # Linux:
    ELF: str = "ELF"
    SH: str = "SH"
    # Other:
    JAR:str = "JAR"
    LNK:str = "LNK"
    URL:str = "URL"
    JNLP:str = "JNLP"
