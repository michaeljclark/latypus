//
//  http_constants.h
//

#ifndef http_constants_h
#define http_constants_h

/*
 * HTTP status codes
 */

extern const char* kHTTPStatusTextNone;
extern const char* kHTTPStatusTextContinue;
extern const char* kHTTPStatusTextSwitchingProtocols;
extern const char* kHTTPStatusTextOK;
extern const char* kHTTPStatusTextCreated;
extern const char* kHTTPStatusTextAccepted;
extern const char* kHTTPStatusTextNonAuthoritativeInformation;
extern const char* kHTTPStatusTextNoContent;
extern const char* kHTTPStatusTextResetContent;
extern const char* kHTTPStatusTextPartialContent;
extern const char* kHTTPStatusTextMultiStatusResponse;
extern const char* kHTTPStatusTextMultipleChoices;
extern const char* kHTTPStatusTextMovedPermanently;
extern const char* kHTTPStatusTextFound;
extern const char* kHTTPStatusTextSeeOther;
extern const char* kHTTPStatusTextNotModified;
extern const char* kHTTPStatusTextUseProxy;
extern const char* kHTTPStatusTextTemporaryRedirect;
extern const char* kHTTPStatusTextBadRequest;
extern const char* kHTTPStatusTextUnauthorized;
extern const char* kHTTPStatusTextPaymentRequired;
extern const char* kHTTPStatusTextForbidden;
extern const char* kHTTPStatusTextNotFound;
extern const char* kHTTPStatusTextMethodNotAllowed;
extern const char* kHTTPStatusTextNotAcceptable;
extern const char* kHTTPStatusTextProxyAuthenticationRequired;
extern const char* kHTTPStatusTextRequestTimeout;
extern const char* kHTTPStatusTextConflict;
extern const char* kHTTPStatusTextGone;
extern const char* kHTTPStatusTextLengthRequired;
extern const char* kHTTPStatusTextPreconditionFailed;
extern const char* kHTTPStatusTextRequestEntityTooLarge;
extern const char* kHTTPStatusTextRequestURITooLarge;
extern const char* kHTTPStatusTextUnsupportedMediaType;
extern const char* kHTTPStatusTextRequestedRangeNotSatisfiable;
extern const char* kHTTPStatusTextExpectationFailed;
extern const char* kHTTPStatusTextUnprocessableEntity;
extern const char* kHTTPStatusTextLocked;
extern const char* kHTTPStatusTextFailedDependency;
extern const char* kHTTPStatusTextInternalServerError;
extern const char* kHTTPStatusTextNotImplemented;
extern const char* kHTTPStatusTextBadGateway;
extern const char* kHTTPStatusTextServiceUnavailable;
extern const char* kHTTPStatusTextGatewayTimeout;
extern const char* kHTTPStatusTextHTTPVersionNotSupported;
extern const char* kHTTPStatusTextInsufficientStorage;

enum HTTPStatusCode {
    HTTPStatusCodeNone =                            0,
    HTTPStatusCodeContinue =                        100,
    HTTPStatusCodeSwitchingProtocols =              101,
    HTTPStatusCodeOK =                              200,
    HTTPStatusCodeCreated =                         201,
    HTTPStatusCodeAccepted =                        202,
    HTTPStatusCodeNonAuthoritativeInformation =     203,
    HTTPStatusCodeNoContent =                       204,
    HTTPStatusCodeResetContent =                    205,
    HTTPStatusCodePartialContent =                  206,
    HTTPStatusCodeMultiStatusResponse =             207, // rfc491
    HTTPStatusCodeMultipleChoices =                 300,
    HTTPStatusCodeMovedPermanently =                301,
    HTTPStatusCodeFound =                           302,
    HTTPStatusCodeSeeOther =                        303,
    HTTPStatusCodeNotModified =                     304,
    HTTPStatusCodeUseProxy =                        305,
    HTTPStatusCodeTemporaryRedirect =               307,
    HTTPStatusCodeBadRequest =                      400,
    HTTPStatusCodeUnauthorized =                    401,
    HTTPStatusCodePaymentRequired =                 402,
    HTTPStatusCodeForbidden =                       403,
    HTTPStatusCodeNotFound =                        404,
    HTTPStatusCodeMethodNotAllowed =                405,
    HTTPStatusCodeNotAcceptable =                   406,
    HTTPStatusCodeProxyAuthenticationRequired =     407,
    HTTPStatusCodeRequestTimeout =                  408,
    HTTPStatusCodeConflict =                        409,
    HTTPStatusCodeGone =                            410,
    HTTPStatusCodeLengthRequired =                  411,
    HTTPStatusCodePreconditionFailed =              412,
    HTTPStatusCodeRequestEntityTooLarge =           413,
    HTTPStatusCodeRequestURITooLarge =              414,
    HTTPStatusCodeUnsupportedMediaType =            415,
    HTTPStatusCodeRequestedRangeNotSatisfiable =    416,
    HTTPStatusCodeExpectationFailed =               417,
    HTTPStatusCodeUnprocessableEntity =             422, // rfc491
    HTTPStatusCodeLocked =                          423, // rfc491
    HTTPStatusCodeFailedDependency =                424, // rfc491
    HTTPStatusCodeInternalServerError =             500,
    HTTPStatusCodeNotImplemented =                  501,
    HTTPStatusCodeBadGateway =                      502,
    HTTPStatusCodeServiceUnavailable =              503,
    HTTPStatusCodeGatewayTimeout =                  504,
    HTTPStatusCodeHTTPVersionNotSupported =         505,
    HTTPStatusCodeInsufficientStorage =             507, // rfc491
    HTTPStatusCodeLast =                            999,
};

struct HTTPStatusEntry
{
    HTTPStatusCode code;
    const char *text;
};

extern HTTPStatusEntry kHTTPStatusTable[];


/*
 * HTTP versions
 */

extern const char* kHTTPVersion10;
extern const char* kHTTPVersion11;
extern const char* kHTTPVersion20;

enum HTTPVersion {
    HTTPVersionNone,
    HTTPVersion10 = 10,
    HTTPVersion11 = 11,
    HTTPVersion20 = 20,
    HTTPVersionLast,
};

struct HTTPVersionEntry
{
    HTTPVersion version;
    const char *text;
};

extern HTTPVersionEntry kHTTPVersionTable[];


/*
 * HTTP request methods
 */

extern const char* kHTTPMethodNONE;

// RFC2616
extern const char* kHTTPMethodGET;
extern const char* kHTTPMethodHEAD;
extern const char* kHTTPMethodPOST;
extern const char* kHTTPMethodPUT;
extern const char* kHTTPMethodDELETE;
extern const char* kHTTPMethodOPTIONS;
extern const char* kHTTPMethodTRACE;
extern const char* kHTTPMethodCONNECT;

// RFC4918 - HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)
extern const char* kHTTPMethodPROPFIND;
extern const char* kHTTPMethodPROPPATCH;
extern const char* kHTTPMethodCOPY;
extern const char* kHTTPMethodMOVE;
extern const char* kHTTPMethodLOCK;

extern const char* kHTTPMethodLast;

enum HTTPMethod {
    HTTPMethodNone,
    HTTPMethodGET,
    HTTPMethodHEAD,
    HTTPMethodPOST,
    HTTPMethodPUT,
    HTTPMethodDELETE,
    HTTPMethodOPTIONS,
    HTTPMethodTRACE,
    HTTPMethodCONNECT,
    HTTPMethodPROPFIND,
    HTTPMethodPROPPATCH,
    HTTPMethodMKCOL,
    HTTPMethodCOPY,
    HTTPMethodMOVE,
    HTTPMethodLOCK,
    HTTPMethodUNLOCK,
    HTTPMethodMKACTIVITY,
    HTTPMethodREPORT,
    HTTPMethodCHECKOUT,
    HTTPMethodMERGE,
    HTTPMethodLast,
};

struct HTTPMethodEntry
{
    HTTPMethod method;
    const char *text;
};

extern HTTPMethodEntry kHTTPMethodTable[];


/*
 * HTTP headers
 */

enum HTTPHeaderType {
    HTTPHeaderTypeNone,
    HTTPHeaderTypeRequest,
    HTTPHeaderTypeResponse,
    HTTPHeaderTypeGeneral,
    HTTPHeaderTypeEntity,
};

struct HTTPHeaderEntry
{
    const char *text;
    HTTPHeaderType type;
};

extern HTTPHeaderEntry kHTTPHeaderTable[];

/*
 * HTTP request headers
 */


extern const char* kHTTPHeaderHost;                // Host: www.example.com
extern const char* kHTTPHeaderUserAgent;           // User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0
extern const char* kHTTPHeaderAccept;              // Accept: image/png,image/*;q=0.8,*/*;q=0.5
extern const char* kHTTPHeaderAcceptLanguage;      // Accept-Language: en-US,en;q=0.5
extern const char* kHTTPHeaderAcceptEncoding;      // Accept-Encoding: gzip, deflate
extern const char* kHTTPHeaderAcceptCharset;       // Accept-Charset: utf-8, iso8859-1;q=0.8
extern const char* kHTTPHeaderAuthorization;       // Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK            (username:password in Base64)
extern const char* kHTTPHeaderCookie;              // Cookie: name=value; name2=value2
extern const char* kHTTPHeaderExpect;              // Expect: 100-continue     (if sending body, server replies "HTTP/1.1 100 Continue" CRLF CRLF)
extern const char* kHTTPHeaderFrom;                // From: user@example.com
extern const char* kHTTPHeaderIfMatch;             // If-Match: "ZXRhZ2V0YWcK"
extern const char* kHTTPHeaderIfModifiedSince;     // If-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT
extern const char* kHTTPHeaderIfNoneMatch;         // If-None-Match: W/"ZXRhZ2V0YWcK"
extern const char* kHTTPHeaderIfRange;             // If-Range: "ZXRhZ2V0YWcK"
extern const char* kHTTPHeaderIfUnmodifiedSince;   // If-Modified-Since: Mon, 02 Apr 2012 02:13:37 GMT
extern const char* kHTTPHeaderMaxForwards;         // Max-Forwards: 9
extern const char* kHTTPHeaderProxyAuthorizatio;   // Proxy-Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQK
extern const char* kHTTPHeaderRange;               // Range: bytes=2048-4095,4096-6143,6144-8191,8192-10239
extern const char* kHTTPHeaderReferer;             // Referer: https://www.google.com.sg/
extern const char* kHTTPHeaderTE;                  // TE: trailers, deflate;q=0.5
extern const char* kHTTPHeaderDepth;               // Depth: 0                                                 (RFC4918 recursion)
extern const char* kHTTPHeaderDestination;         // Destination: /foo/bar                                    (RFC4918 destination of COPY or MOVE)
extern const char* kHTTPHeaderIf;                  // If: (<locktoken:a-write-lock-token> ["I am an ETag"])    (RFC4918 extended if)
extern const char* kHTTPHeaderLockToken;           // Lock-Token: <opaquelocktoken:a515cfa4-5da4>              (RFC4918 lock token)
extern const char* kHTTPHeaderOverwrite;           // Overwrite: "T"                                           (RFC4918 overwrite)
extern const char* kHTTPHeaderTimeout;             // Timeout: Infinite, Second-4100000000                     (RFC4918 lock timeout)


/* response headers */

extern const char* kHTTPHeaderServer;              // Server: objstore/0.0
extern const char* kHTTPHeaderSetCookie;           // Set-Cookie: name2=value2; Expires=Wed, 09 Jun 2021 10:18:14 GMT
extern const char* kHTTPHeaderAcceptRanges;        // Accept-Ranges: bytes
extern const char* kHTTPHeaderWWWAuthenticate;     // Basic realm="myRealm"    (included in 401 Unauthorized response messages)
extern const char* kHTTPHeaderAge;                 // Age: 60                  (age in seconds sent by caches)
extern const char* kHTTPHeaderETAG;                // ETag: "ZXRhZ2V0YWcK"
extern const char* kHTTPHeaderLocation;            // Location: http://www.example.com/redirected/
extern const char* kHTTPHeaderProxyAuthenticate;   // Proxy-Authenticate: Basic realm="myRealm"
extern const char* kHTTPHeaderRetryAfter;          // Retry-After: 120         (can be sent with 503 (Service Unavailable))
extern const char* kHTTPHeaderTrailers;            // Trailers: Content-MD5    (chunked encoding trailing headers)


/* general headers */

extern const char* kHTTPHeaderConnection;          // Connection: keep-alive
extern const char* kHTTPHeaderCacheControl;        // Cache-Control: max-age=0
extern const char* kHTTPHeaderDate;                // Date: Sat, 09 Nov 2013 11:25:06 GMT
extern const char* kHTTPHeaderTransferEncoding;    // Transfer-Encoding: chunked
extern const char* kHTTPHeaderUpgrade;             // Upgrade: HTTP/2.0
extern const char* kHTTPHeaderVary;                // Vary: Accept
extern const char* kHTTPHeaderVia;                 // Via: 1.0 ricky
extern const char* kHTTPHeaderWarning;             // Warning: 37 "P1" "My hovercraft is full of eels"
extern const char* kHTTPHeaderDAV;                 // DAV: 1                   (RFC4918 compliance: "1" | "2" | "3" | extend)


/* entity header fields */

extern const char* kHTTPHeaderAllow;               // Allow: GET, HEAD, PUT
extern const char* kHTTPHeaderContentEncoding;     // Content-Encoding: gzip
extern const char* kHTTPHeaderContentLanguage;     // Content-Language: en
extern const char* kHTTPHeaderContentLength;       // Content-Length: 8986
extern const char* kHTTPHeaderContentLocation;     // Content-location: /index.en.html
extern const char* kHTTPHeaderContentMD5;          // Content-MD5: OQroDtMY0ttn/mMQJEZrjA==    (base64 of binary MD5)
extern const char* kHTTPHeaderContentRange;        // Content-Range: bytes 0-499/1234          (first 500 bytes of 1234 byte object)
extern const char* kHTTPHeaderContentType;         // Content: text/html
extern const char* kHTTPHeaderExpires;             // Expires: Thu, 01 Dec 1994 16:00:00 GMT
extern const char* kHTTPHeaderLastModified;        // Last-Modified: Fri, 12 Apr 2013 00:31:11 GMT
extern const char* kHTTPHeaderPragma;              // Pragma: no-cache                         (note this is equivalent to Cache-Control: no-cache)


/* header field tokens */

extern const char* kHTTPTokenClose;
extern const char* kHTTPTokenKeepalive;


/* http_constants */

#define USE_CPP_STRING_MAPS 1

struct http_constants
{
#if USE_CPP_STRING_MAPS
    typedef std::map<std::string,int>                       MapTextValue;
    typedef std::pair<std::string,int>                      PairTextValue;
    typedef std::map<int,std::string>                       MapValueText;
    typedef std::pair<int,std::string>                      PairValueText;
    typedef std::map<std::string,std::string>               MapTextText;
    typedef std::pair<std::string,std::string>              PairTextText;
#else
    struct str_less
    { bool operator()(const char *a, const char *b) const { return strcmp(a, b) < 0; } };

    typedef std::map<const char *,int,str_less>             MapTextValue;
    typedef std::pair<const char *,int>                     PairTextValue;
    typedef std::map<int,const char *>                      MapValueText;
    typedef std::pair<int,const char *>                     PairValueText;
    typedef std::map<const char *,const char *,str_less>    MapTextText;
    typedef std::pair<const char *,const char *>            PairTextText;
#endif
    
    static MapValueText status_code_text;
    static MapTextValue version_text_code;
    static MapValueText version_code_text;
    static MapTextValue method_text_code;
    static MapValueText method_code_text;
    static MapTextText  header_text;

    static void init();
    
    static const char* get_status_text(int code);
    static const HTTPVersion get_version_type(const char* text);
    static const char* get_version_text(HTTPVersion version);
    static const HTTPMethod get_method_type(const char* text);
    static const char* get_method_text(HTTPMethod method);
    static const char* get_header_text(const char* text);
};

#endif
