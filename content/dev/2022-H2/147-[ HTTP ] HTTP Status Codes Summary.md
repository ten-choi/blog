---
title: "[ HTTP ] HTTP Status Codes Summary"
labels: ["ETC","Data Communication","http","Archive"]
published: true
date: 2022-09-02T15:10:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 147
tistoryUrl: "https://yeolceo.tistory.com/147"
tistoryCategory: "ETC/데이터 통신"
tistoryTags: ["http"]
tistoryPostedAt: "2022-09-02 15:10:11"
language: en
bloggerPostId: "3990566407510457479"
---
## **\- HTTP Status Code** 

It helps to know the basic structure of status codes.  

**1xx (Informational)**: The request was received and the process continues

1.  100: The request you sent is in progress

**2xx (Success)**: The request was successfully received, understood, and accepted

1.  200: The request you sent was carried out successfully
2.  201: The request you sent succeeded and a new resource was created
3.  202: The request was received, but it seems nothing in particular was returned

**3xx (Redirection)**: Further action is needed to complete the request

1.  302: The URI of the requested resource has changed temporarily

**4xx (Client Error)**: The request has bad syntax or cannot be fulfilled

1.  400: The server can't understand the request because of bad syntax
2.  401: No credentials for access exist at all
3.  403: Insufficient or no access rights
4.  404: The server can't find the requested page

**5xx (Server Error)**: The server failed to fulfill an apparently valid request

1.  500: An error occurred on the server and it can't process the request
2.  502: An error caused by a gateway while the server was processing the request

**200, 201, 301, 303, 400, 401, 404, 500, 503**

**\--------------------------------------------------------------------------------**1xx : **Information**

2xx : **Successful**

3xx : **Redirection**

4xx : **Client Error**

5xx : **Server Error**

****\--------------------------------------------------------------------------------****

100 : Continue.

101 : Switching Protocols.

**\--------------------------------------------------------------------------------**

200 : OK, sent successfully without errors.

202 : Accepted, the server has received the client's command.

203 : Non-Authoritative Information, the server sent only part of what the client requested.

204 : No Content, the client's request was processed but there's no data to send.

205 : Reset Content.

206 : Partial Content.

**\--------------------------------------------------------------------------------**

300 : Multiple Choices, requests data that was recently moved.

301: Moved Permanently, the requested data has permanently moved to a new URL.

302: Found, indicates that the requested data is temporarily at a different URL.

303: See Other, there's a problem because the requested data was not changed.

304: Not modified.

305: Use Proxy.

**\--------------------------------------------------------------------------------**

400 : Bad Request, the request failed.  
The server can't understand the request because of a syntax error. The client should not repeat the request without modifying it.

401.1: Unauthorized, no permission (logon failed).

This error occurs when the logon request doesn't match the permissions on the server. In this case, you need to ask the server administrator to grant you permission to access the resource you requested.

401.2: Unauthorized, no permission (logon failed due to server configuration).

This error occurs when the logon request doesn't match the permissions on the server. It's usually caused by not sending a proper www-authenticate header field.

401.3: Unauthorized, no permission (due to the ACL on the resource).

This error occurs when the client can't access a particular resource. The resource could be a page, a file specified in the client's address bar, or another file used when the client goes to that address. Double-check the full address you're trying to access, and confirm with the web server administrator that you have permission to access the resource.

401.4: Unauthorized, no permission (authorization failed by a filter).  
This error means the web server has a filter program installed to verify users connecting to the server. The authentication process used to connect to the server was rejected by this filter program.

401.5: Unauthorized, no permission (authorization failed by an ISAPI/CGI application).  
This error means an ISAPI or CGI program is installed at the address of the web server you're trying to use, and it verifies user permissions. The authentication process used to connect to the server was rejected by this program.

402: Payment Required, reserved.

403.1: Forbidden (execute access forbidden).  
This error occurs when you try to run a CGI, ISAPI, or other executable file in a directory that doesn't allow execution.

403.2: Forbidden (read access forbidden).  
This error occurs when there's no default page available in the directory the browser accessed, or when you try to view an HTML page in a directory that only has Execute or Script permissions.

403.4: Forbidden (SSL required).  
This error occurs when the page you're trying to access is secured with SSL. To view it, you need to be able to use SSL before entering the address.

403.5: Forbidden (SSL 128 required).  
This error occurs when the page you're trying to access is secured with SSL. To view this resource, your browser must support that level of SSL. Check whether your browser supports 128-bit SSL.

403.6: Forbidden (IP address rejected).  
This error occurs when the server has an IP address that isn't allowed to access the site, and the user tries to access it from that address.

403.7: Forbidden (client certificate required).  
This error occurs when the resource you're trying to access requires your browser to present a client SSL certificate so the server can recognize you. This is used to prove that you're a user allowed to use the resource.

403.8: Forbidden (site access denied).  
This error occurs when the web server isn't processing requests, or when you're not allowed to access the site.

403.9: Forbidden (too many users connected).  
This error occurs when the web server is BUSY and can't process your request. Try again in a little while.

403.10: Forbidden (invalid configuration).  
There's currently a problem with the web server's configuration.

403.11: Forbidden (password changed).  
This error occurs when you enter the wrong password during user verification. Refresh the page and try again.

403.12: Forbidden (mapper denied access).  
Your client certificate map was denied access to the website. Ask the site administrator for client certificate permission. You can also change your client certificate.

404: Not Found, the document can't be found.  
The web server couldn't find the requested file or script. Look at the URL again and check that the address was entered correctly.  
\- Fix: a. Tools ▶ Internet Options ▶ General ▶ delete cookies, delete files, clear history  
b. Tools ▶ Internet Options ▶ Advanced ▶ uncheck \[Always send URLs as UTF-8\].

405: Method not allowed.  
The resource isn't allowed to be used to perform the method specified in the request line. Check that the resource you requested has the appropriate MIME type.

406: Not Acceptable.  
The resource needed for the request can only generate Response entities whose content is "Not Acceptable" according to the Accept header sent with the request.

407: Proxy Authentication Required.  
You need to authenticate with the proxy server for the request to go through. Log on to the proxy server and try again.

408: Request timeout, the request took too long.

409: Conflict.

410: Gone, permanently unavailable.

411: Length Required.

412: Precondition Failed.  
This occurs when the server tests the value of one or more preconditions in the Request-header fields and they come out FALSE. The client preconditions are intended to prevent the current resource's meta-information from being applied to more than one resource.

413: Request entity too large.

414: Request-URI too long, the requested URI is too long.  
The server refused to fulfill the request because the requested URI was too long. This rare situation only happens in cases like these: the client improperly converted a POST request into a GET with long query information; the client ran into a redirection problem; or the server is under attack by a client trying to exploit security holes in the fixed-length memory buffers some servers use to read and process the requested URI.

415: Unsupported media type.

**\--------------------------------------------------------------------------------**

500 : Internal Server Error.  
The web server can't carry out the request. Try requesting it again.

501: Not Implemented.  
The web server doesn't support the functionality needed to carry out the request. Check the URL where the error occurred, and if the problem continues, contact the web server administrator.

502: Bad gateway, bad gateway state / server overloaded.  
This occurs when a server acting as a gateway or proxy receives an invalid response from the upstream server it forwarded the request to. If the problem continues, consult the web server administrator.

503: Service Unavailable, the external service is down, currently stopped, or otherwise unavailable.  
The server can't handle the request right now because of temporary overload or maintenance. This is a temporary condition that will ease after some delay. The length of the delay may be indicated in a Retry-After header. If no Retry-After is given, the client should handle the response as it would a 500 response. The existence of this status code doesn't mean a server must use it when overloaded; some servers may simply prefer to refuse the connection.

504: Gateway timeout.

505: HTTP Version Not Supported.
