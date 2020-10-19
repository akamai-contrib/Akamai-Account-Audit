available_features  = {

'allHttpInCacheHierarchy' : \
'This feature helps with Advanced Cache Hierarchy & Optimization. \
Use common tactics of leveraging the widely distributed Akamai GHOSTs as the cache hierarchy and \
the three fundamental cache parent forward policies - Tiered Distribution, Site Shield, and Sureroute - \
to improve both cache hit rates and forward performance during cache misses. \
More inforamtion can be found here: https://ac.akamai.com/groups/gc-service-delivery/blog/2017/05/17/advanced-cache-hierarchy-optimization ',
'caching' : \
'Control content caching on edge servers \
 whether or not to cache, whether to honor the origins caching headers \
 and for how long to cache. Note that any NO_STORE or BYPASS_CACHE HTTP \
 headers set on the origin\'s content overrides this behavior.',
'allowTransferEncoding': \
'Controls whether to allow or deny Chunked Transfer\
Encoding (CTE) requests to pass to your origin. \
If your origin supports CTE, you should enable this behavior. \
This behavior also protects against a known issue when pairing http2 and \
 webdav behaviors within the same rule tree, in which case it is required.' ,
'apiPrioritization' : \
'Enables the API Prioritization Cloudlet, \
which maintains continuity in user experience by serving an alternate static \
response when load is too high. You can configure rules using either the Cloudlets \
Policy Manager application or the Cloudlets API. The feature is designed to serve static\
 API content, such as fallback JSON data. To serve non-API HTML content\
 use the visitorPrioritization behavior.'
}