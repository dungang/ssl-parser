<?php
$host = 'www.taobao.com';
$stream = stream_context_create([
    'ssl'=>[
        "allow_self_signed" => true,
        "sni_enabled" => true,
        'peer_name' => $host,
        'verify_peer'=> false, //是否需要验证 SSL 证书。
        'verify_peer_name'=> false, //Require verification of peer name.
        'capture_peer_cert'=>true, //如果设置为 TRUE 将会在上下文中创建 peer_certificate 选项， 该选项中包含远端证书。
        'capture_peer_cert_chain'=>true , //如果设置为 TRUE 将会在上下文中创建 peer_certificate_chain 选项， 该选项中包含远端证书链条。
    ]
]);

$data = stream_socket_client('ssl://'.$host.':443',$errorNo,$errorMessage,30,STREAM_CLIENT_CONNECT,$stream);

$ssl = [];
if ($data) {
    $params = stream_context_get_params($data);
    $options = stream_context_get_options($data);
    $ssl['peer_certificate'] = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
    $chains = $params['options']['ssl']['peer_certificate_chain'];
    if(is_array($chains)) {
        $cert_chain_pems = [];
        $last_cn = null;
        $length = count($chains);
        foreach($chains as $key => $chain){
            $chain_data = openssl_x509_parse($chain);
            if ($last_cn === null) {
                $last_cn = $chain_data['issuer']['CN'];
            } else if (strcmp($last_cn,$chain_data['subject']['CN']) !==0 ){
                if ($length != $key + 1) {
                    throw new Exception('Issuer does not match the next certificate CN. Chain order is probably wrong.');
                }
            }
            $pem = "";
            openssl_x509_export($chain,$pem);
            $cert_chain_pems[$key]=$pem;
            $ssl['peer_certificate_chains'][$key]['data'] = $chain_data;
        }
        $file = 'PEM-' . genUuid() . '.pem';
        file_put_contents($file,trim(implode("\n", array_reverse($cert_chain_pems))));

        $cmd = 'openssl verify -verbose -purpose any';
        $cwd = getcwd();
        $cmd .= ' -CAfile "' . $cwd . '/cacert.pem" "' . $cwd . '/'.$file.'"';
        $cmd = str_replace('\\','/',$cmd);
        echo $cmd . "\n";
        $cmd_result = escapeshellcmd($cmd);
        if (preg_match('/OK/',$cmd_result)){

        }

    }

}

function connectionData()
{

}

function genUuid() {
    //from stack overflow.
    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        // 32 bits for "time_low"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

        // 16 bits for "time_mid"
        mt_rand( 0, 0xffff ),

        // 16 bits for "time_hi_and_version",
        // four most significant bits holds version number 4
        mt_rand( 0, 0x0fff ) | 0x4000,

        // 16 bits, 8 bits for "clk_seq_hi_res",
        // 8 bits for "clk_seq_low",
        // two most significant bits holds zero and one for variant DCE1.1
        mt_rand( 0, 0x3fff ) | 0x8000,

        // 48 bits for "node"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
}