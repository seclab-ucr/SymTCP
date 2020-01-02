##! HTTP requests with blacklisted keywords detection in HTTP.

@load base/frameworks/notice
@load base/protocols/http

module HTTP;

export {
    redef enum Notice::Type += {
        ## Indicates that a host sending HTTP requests with URL 
        ## containing blacklisted keywords was detected.
        Bad_Keyword_Request,
    };

    const match_bad_keywords_uri = /ultrasurf/;
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=3
{
    if ( match_bad_keywords_uri in unescaped_URI ) {
        NOTICE([$note=Bad_Keyword_Request,
                $msg=unescaped_URI]);
    }
}