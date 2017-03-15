<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 15:40
 */

namespace dungang\sslparser;


class SSLParser
{

    public $host = 'localhost';

    public $port = '443';

    public $timeout = 30;

    private $dsn;

    private $sslStream;

    private $certificateData;

    public function  __construct($host,$port=443) {
        $this->host = $host;
        $this->port = $port;
        $this->dsn = 'ssl://' . $host . ':' . $port;
    }

    public function parser() {

        $this->certificateData = $this->getStreamData();
        return $this->certificateData;

    }

    public function getStreamData()
    {
        $this->sslStream = stream_context_create([
            'ssl'=>[
                "allow_self_signed" => true,
                "sni_enabled" => true,
                'peer_name' => $this->host,
                'verify_peer'=> false, //是否需要验证 SSL 证书。
                'verify_peer_name'=> false, //Require verification of peer name.
                'capture_peer_cert'=>true, //如果设置为 TRUE 将会在上下文中创建 peer_certificate 选项， 该选项中包含远端证书。
                'capture_peer_cert_chain'=>true , //如果设置为 TRUE 将会在上下文中创建 peer_certificate_chain 选项， 该选项中包含远端证书链条。
            ]
        ]);

        $data = stream_socket_client(
           $this->dsn,$errorNo,$errorMessage,
           $this->timeout,STREAM_CLIENT_CONNECT,
           $this->sslStream);
        if (!$data) {
            throw new SSLParserException($errorNo,$errorMessage);
        }
        return $data;
    }
}