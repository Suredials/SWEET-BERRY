<?php
$requestId = $_SERVER['HTTP_X_SWEETBERRY_REQUEST_ID'] ?? '';
$started = microtime(true);
$base = ['timestamp'=>$started,'request_id'=>$requestId,'namespace_pid'=>getmypid(),'source_ip'=>$_SERVER['HTTP_X_FORWARDED_FOR'] ?? 'unattributed','script'=>$_SERVER['SCRIPT_NAME'] ?? '', 'sensor'=>'php-runtime'];
file_put_contents('php://stderr',json_encode(array_merge($base,['kind'=>'php_request_start']))."\n");
register_shutdown_function(function() use ($base,$started) {
 file_put_contents('php://stderr',json_encode(array_merge($base,['timestamp'=>microtime(true),'kind'=>'php_request_end','duration_ms'=>(microtime(true)-$started)*1000,'status'=>http_response_code()]))."\n");
});
