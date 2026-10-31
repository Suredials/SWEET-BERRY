<?php
// Deliberate lab vulnerability: executable file types are accepted and publicly served.
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['attachment'])) { http_response_code(400); echo json_encode(['error'=>'Attachment required']); exit; }
$file = $_FILES['attachment'];
if ($file['error'] !== UPLOAD_ERR_OK || $file['size'] > 5*1024*1024) { http_response_code(413); echo json_encode(['error'=>'Upload failed or too large']); exit; }
$name = bin2hex(random_bytes(5)).'-'.preg_replace('/[^A-Za-z0-9_.-]/','_',basename($file['name']));
if (!move_uploaded_file($file['tmp_name'], __DIR__.'/uploads/'.$name)) { http_response_code(500); echo json_encode(['error'=>'Storage unavailable']); exit; }
echo json_encode(['status'=>'received','file'=>$name,'url'=>'/uploads/'.$name,'sha256'=>hash_file('sha256',__DIR__.'/uploads/'.$name)]);
