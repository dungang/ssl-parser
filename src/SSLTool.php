<?php
/**
 * Author: dungang
 * Date: 2017/3/18
 * Time: 19:09
 */

namespace dungang\sslparser;



class SSLTool
{
    const MAX_PATH = 10;

    const ISSUERS_DATA_DIR = 'issuers_hash';

    const TMP_DIR = 'tmp';

    const SIGN_TYPE_ROOT = 'Root CA';
    const SIGN_TYPE_INTER = 'InterMedia CA';
    const SIGN_TYPE_SELF = 'Self Signed';
    const SIGN_TYPE_CA = 'Signed By CA';

    public $host;

    public $port;

    public $timeout = 30;

    protected $rootCADir='md5';

    public $fileMaxSaveDays = 5;

    public $dataDir = '/tmp/ssl';

    protected $timestamp;

    protected $certPem;

    public $ip;

    public function __construct($host, $ip,$port = 443,$dataDir='/tmp/ssl')
    {
        $this->host = $host;
        $this->port = $port;
        $this->ip = $ip;
        $this->timestamp = time();
        $this->dataDir = $dataDir;
        $this->rootCADir = $dataDir . '/md5/';
    }


    public function parser()
    {
        $streamData = $this->getStream($this->host, $this->timeout);

        $streamParams = stream_context_get_params($streamData);
        $options = $streamParams['options']['ssl'];
        $info = $this->parserChain($options['peer_certificate']);
        $this->certPem = $this->convert2pem($options['peer_certificate']);
        $rawData = $this->parseStreamChains($this->hashSubject($info['subject']),$options['peer_certificate_chain']);
        return [
            'info' => $info,
            'streamInfo' => $rawData['rawChains'],
            'shouldInfo' => $rawData['mapChains'],
            'ocsp' => $this->parseOCSPByShell($info,$rawData),
            'chainsOrderRight'=>$this->checkChainsOrder($rawData)
        ];
    }

    public function getStream($host, $timeout)
    {
        $dsn = 'ssl://' . $this->ip . ':' . $this->port;
        $sslStream = stream_context_create([
            'ssl' => [
                "allow_self_signed" => true,
                "sni_enabled" => true,
                'peer_name' => $host,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'capture_peer_cert' => true,
                'capture_peer_cert_chain' => true
            ]
        ]);
        $data = stream_socket_client(
            $dsn, $errorNo, $errorMessage,
            $timeout, STREAM_CLIENT_CONNECT,
            $sslStream);
        if (!$data) {
            throw new \Exception($errorNo, $errorMessage);
        }
        return $data;
    }


    public function parserChain($chain) {
        $info = openssl_x509_parse($chain);
        $info['subject'] = array_map(function($value){
            if(is_array($value)) {
                return implode(' ',$value);
            }
            return $value;
        },$info['subject']);
        $info['issuer'] = array_map(function($value){
            if(is_array($value)) {
                return implode(' ',$value);
            }
            return $value;
        },$info['issuer']);
        return $info;
    }

    public static function parseHostname($uHostname){
        # parses the URL and if no extea IP given, returns all A/AAAA records for that IP.
        # format raymii.org:1.2.34.56 should do SNI request to that ip.
        # parts[0]=host, parts[1]=ip
        $parts = explode(":", $uHostname, 2);
        if (idn_to_ascii($parts[0])) {
            $parts[0] = idn_to_ascii($parts[0]);
        }
        $parts[0] = preg_replace('/\\s+/', '', $parts[0]);
        $parts[0] = preg_replace('/[^A-Za-z0-9\.\:-]/', '', $parts[0]);
        $hostname = mb_strtolower($parts[0]);

        if (count($parts) > 1) {
            $parts[1] = preg_replace('/\\s+/', '', $parts[1]);
            $parts[1] = preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $parts[1]);
            if (filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) or filter_var($parts[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
                $ip = mb_strtolower($parts[1]);
            }
        } else {
            if (filter_var($hostname, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
                $ip = $hostname;
            } else {
                $dns_a_records = dns_get_record($hostname, DNS_A);
                $dns_aaaa_records = dns_get_record($hostname, DNS_AAAA);
                $dns_records = array_merge($dns_a_records, $dns_aaaa_records);
                if (count($dns_a_records) > 1 or count($dns_aaaa_records) > 1 or (count($dns_a_records) + count($dns_aaaa_records) > 1)) {
                    $result = array('hostname' => $hostname, 'multiple_ip' => $dns_records);
                    return $result;
                } else {
                    $ip = self::fixedGetHostByName($hostname);
                }
            }
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip = "[" . $ip . "]";
        }

        $result = array('hostname' => $hostname, 'ip' => $ip);
        return $result;
    }


    public static function fixedGetHostByName($host) {
        $ips = dns_get_record($host, DNS_A + DNS_AAAA);
        sort($ips);
        $ip = '';
        foreach ($ips as $key => $value) {
            if ($value['type'] === "AAAA") {
                $ip = $value['ipv6'];
            } elseif ($value['type'] === "A") {
                $ip = $value['ip'];
            } else {
                return false;
            }
        }
        if ($ip != $host) {
            return $ip;
        } else {
            return false;
        }
    }

    /**
     * @param $serverSubjectHash
     * @param $chains
     * @return array
     */
    public function parseStreamChains($serverSubjectHash,$chains)
    {
        $data = [];
        $map = [];
        $rawHasRootCA = false;
        $recHasRootCA = false;
        foreach ($chains as $peerCertChain) {
            $info =  $this->parserChain($peerCertChain);
            $subject = $this->hashSubject($info['subject']);
            $issuer = $this->hashSubject($info['issuer']);
            $raw = [
                'info'=>$info,
                'pem'=>$this->convert2pem($peerCertChain),
                'subjectHash'=>$subject,
                'issuerHash'=>$issuer,
                'signType'=> $this->getCertSignType($info)
            ];
            if ($raw['signType'] == self::SIGN_TYPE_ROOT) $rawHasRootCA = true;
            $data[] = $raw;
            $map[$subject] = $raw;
        }

        $length = count($data);
        if ($length > 0 ) {
            $last = $data[$length-1];
            $last = $this->checkLastChainIsLocalRootCA($last);
            $data[$length-1] = $last;
            if ($last['signType'] == self::SIGN_TYPE_ROOT) {
                $rawHasRootCA = true;
            }

            if (!$rawHasRootCA) {

                $constructions = $this->constructChains($last);

                foreach($constructions as $chain) {
                    $map[$chain['subjectHash']] = $chain;
                    if ($chain['signType'] == self::SIGN_TYPE_ROOT) $recHasRootCA = true;
                }
            }
        }
        //print_r($map);die;
        $mapChains = $this->reSortChains($map,$serverSubjectHash);
//        $length = count($mapChains);
//        if ($length > 0 ) {
//            $last = $mapChains[$length-1];
//            $last = $this->checkLastChainIsLocalRootCA($last);
//            $mapChains[$length-1] = $last;
//            if ($last['signType'] == self::SIGN_TYPE_ROOT) {
//                $recHasRootCA = true;
//            }
//        }
        return [
            'rawHasRootCA' => $rawHasRootCA,
            'recHasRootCA' => $recHasRootCA,
            'rawChains'=>$data,
            'mapChains'=>$mapChains,
        ];
    }


    public function checkLastChainIsLocalRootCA($chain)
    {
        $issCaFile = $this->getRootCAFile($chain['info']['issuer']);
        $subCaFile = $this->getRootCAFile($chain['info']['subject']);
        if (!$issCaFile && $subCaFile) {
            $chain['signType'] = self::SIGN_TYPE_ROOT;
            $caContent = file_get_contents($subCaFile);
            if(strcmp(trim($caContent),trim($chain['pem']))!=0) {
                $chain['pemNotMatch'] = true;
                $chain['correctPem'] = $caContent;
            }
        }
        return $chain;
    }

    public function checkChainsOrder($rawData)
    {

        $streamInfo = $rawData['rawChains'];
        $constructInfo = $rawData['mapChains'];
        $streamCount = count($streamInfo);
        $constructCount = count($constructInfo);
        if ($streamCount == 1 or $streamCount < $constructCount - 1) {
            return false;
        }
        foreach($streamInfo as $k => $chain){
            if (strcmp($chain['subjectHash'],$constructInfo[$k]['subjectHash'])!==0) {
                return false;
            }
        }
        return true;
    }


    public function constructChains($peerChain, $number = 0, $result = [])
    {
        if ($number > self::MAX_PATH) {
            return $result;
        }
        $Info =  $peerChain['info'];
        $result[$peerChain['subjectHash']] = $peerChain;
        $uris = $this->parseAuthorityInfoAccess($Info);
        if (is_array($uris)) {
            if (isset($uris['CA Issuers'])) {
                $url = $result[$number]['issuersUrl'] =  trim($uris['CA Issuers']);
                $urlHashDirPrefix = $this->getDirPath(self::ISSUERS_DATA_DIR) . md5($url);
                $issuersCerFile = $urlHashDirPrefix . '.cer';
                $issuersPemFile = $urlHashDirPrefix . '.pem';
                if ($this->invalidFile($issuersCerFile)) {
                    $this->saveRemoteFile($url,$issuersCerFile);
                    $this->isNormalCertificateFile($issuersCerFile);
                }
                if (file_exists($issuersCerFile)) {
                    $issuersChain = $this->caIssuersToChain($issuersCerFile);
                    $issuersInfo = $this->parserChain($issuersChain);
                    @unlink($issuersCerFile);

                    $issuersPem = $this->convert2pem($issuersChain);
                    if ($this->invalidFile($issuersPemFile)) {
                        file_put_contents($issuersPemFile,trim($issuersPem));
                    }
                    $number += 1;
                    $subject = $this->hashSubject($issuersInfo['subject']);
                    $issuer = $this->hashSubject($issuersInfo['issuer']);
                    return $this->constructChains([
                        'info'=>$issuersInfo,
                        'pem'=> $issuersPem,
                        'subjectHash'=>$subject,
                        'issuerHash'=>$issuer,
                        'signType'=> $this->getCertSignType($issuersInfo)
                    ], $number, $result);
                }
            }
        }
        return $result;
    }

    public function getCertSignType($info){
        // self signed/ca/ca root
        if (strpos($info['extensions']['basicConstraints'], "CA:TRUE") !== false
            && $info['issuer']['CN'] == $info['subject']['CN'] ) {
            return self::SIGN_TYPE_ROOT;
        } else if (strpos($info['extensions']['basicConstraints'], "CA:TRUE") !== false) {
            return self::SIGN_TYPE_INTER;
        } else if ($info['issuer']['CN'] == $info['subject']['CN']) {
            return self::SIGN_TYPE_SELF;
        } else {
            return self::SIGN_TYPE_CA;
        }
    }

    public function reSortChains($map,$start,$result=[]) {
        if (!empty($map[$start])) {
            $chain = $map[$start];
            $result[] = $chain;
            if (!empty($chain['issuerHash'])) {
                if ($start == $chain['issuerHash']) {
                    return $result;
                } else {
                    return $this->reSortChains($map,$chain['issuerHash'],$result);
                }
            }
        }
        return $result;


    }

    public function hashSubject($subject) {

        ksort($subject);
        return md5(implode('/',array_values($subject)));
    }


    public function convertPemToDerCertFile($pemFile,$derFile)
    {
        $cmd = 'openssl x509 -in %s -inform PEM -out %s -outform DER';
        shell_exec(sprintf($cmd,$this->escapeShellPath($pemFile),$this->escapeShellPath($derFile)));
    }

    public function getPemFragmentsFromInfo($info)
    {
        $pemFragments = [];
        for ($i = 1; $i < count($info); $i++) {
            $pemFragments[] = $info[$i]['pem'];
        }
        return $pemFragments;
    }


    public function parseOCSPByShell($Info, $rawData)
    {
        $result = [];
        $result['validateOCSPResponse'] = 'failed';
        $streamInfo = $rawData['rawChains'];
        $constructInfo = $rawData['mapChains'];
        $rawHasRootCA= $rawData['rawHasRootCA'];
        $recHasRootCA= $rawData['recHasRootCA'];
        // ocsp
        if (isset($Info['extensions']['authorityInfoAccess'])) {

            if ($uris = $this->parseAuthorityInfoAccess($Info)) {
                if (empty($uris['OCSP'])) {
                    $result["errorMessage"] = "No OCSP URI found in certificate";
                } else {
                    $uri = $uris['OCSP'];
                    $issuersPemFragments = $this->getPemFragmentsFromInfo($streamInfo);
                    $issuersFilePrefix = $this->escapeShellPath($this->getDirPath(self::TMP_DIR) . self::uuid());
                    $issuersPemFile = $issuersFilePrefix. '.issuers.pem';
                    $rootChainsPemFile = $issuersFilePrefix. '.root.pem';

                    //gen issuers ca
                    file_put_contents($issuersPemFile, trim(implode("", $issuersPemFragments)));

                    if ($rawHasRootCA) {
                        $rootChainsPemFile = $issuersPemFile;
                    } else {
                        $length = count($constructInfo);
                        $lastChain = $constructInfo[$length-1];
                        if ($recHasRootCA) {
                            $issuersPemFragments[] = $lastChain['pem'];
                        } else {
                            if ($caFile = $this->getRootCAFile($lastChain['info']['issuer'])) {
                                $issuersPemFragments[] = file_get_contents($caFile);
                            } else {
                                $result["errorMessage"] = "No find root ca pem file";
                                return $result;
                            }
                        }
                        //gen root ca chain
                        file_put_contents($rootChainsPemFile, trim(implode("", $issuersPemFragments)));
                    }

                    $ocspHost = parse_url($uri, PHP_URL_HOST);
                    $result['ocspUri'] = $uri;
                    $serverPemFile = $issuersFilePrefix . '.server.pem';

                    //gen server ca
                    file_put_contents($serverPemFile,trim($this->certPem));

                    //exec ocsp test shell
                    $cmd = 'openssl ocsp -resp_text -no_nonce -CAfile %s -issuer %s -cert %s -url "%s" -header HOST %s 2>&1';
                    $realCmd = sprintf($cmd, $rootChainsPemFile, $issuersPemFile, $serverPemFile,
                        escapeshellcmd($uri), escapeshellcmd($ocspHost));
                    $output = shell_exec($realCmd);

                    //delete tmp file
                    @unlink($serverPemFile);
                    @unlink($issuersPemFile);
                    @unlink($rootChainsPemFile);

                    $matches = [];
                    $outs = [];

                    //check cmd output
                    if (preg_match_all('/[ \t\f]*(.*?)\:[ \t\f]+(.*)$/xmD', $output, $matches)) {
                        if (count($matches) == 3) {
                            foreach ($matches[1] as $k => $name) {
                                $outs[$name] = trim($matches[2][$k]);
                            }

                        }
                    }
                    $result['OCSPResponseStatus'] = $outs['OCSP Response Status'];
                    if (isset($outs[$serverPemFile])) {
                        $status = $outs[$serverPemFile];
                        if ($status == 'good') {
                            $result["certificateStatus"] = "good";
                            $result['validateOCSPResponse'] = preg_match('/Response verify OK/', $output) ? "success" : "failed";
                        } else if ($status == "revoked") {
                            $result["certificateStatus"] = "revoked";
                        } else {
                            $result["certificateStatus"] = "unkown";
                        }
                    }

                    if (isset($outs["This Update"])) {
                        $result["thisUpdate"] = $outs["This Update"];
                    }
                    if (isset($outs["Next Update"])) {
                        $result["nextUpdate"] = $outs["Next Update"];
                    }
                    if (isset($outs["Reason"])) {
                        $result["reason"] = $outs["Reason"];
                    }
                    if (isset($outs["Revocation Time"])) {
                        $result["revocationTime"] = $outs["Revocation Time"];
                    }
                }

                if (empty($uris['CA Issuers'])) {
                    $result["errorMessage"] = "No issuer cert provided. Unable to send OCSP request.";
                }
            } else {
                $result["errorMessage"] = "No OCSP URI found in certificate";
            }
        } else {
            $result["errorMessage"] = "No OCSP URI found in certificate";
        }
        return $result;
    }

    public function parseAuthorityInfoAccess($Info)
    {
        $uris = [];
        if (isset($Info['extensions']['authorityInfoAccess'])) {
            $access = $Info['extensions']['authorityInfoAccess'];
            if (is_string($access) && preg_match_all('/(.*?)\s+\-\s+URI\:(.*)/m', $access, $matches)) {
                if (count($matches) == 3) {
                    foreach ($matches[1] as $key => $word) {
                        $uris[$word] = $matches[2][$key];
                    }
                }
            }
        }
        return $uris;
    }

    /****************************************
     *                                      *
     * tools function                       *
     *                                      *
     ***************************************/

    public static $dict = [
        'validateOCSPResponse'=>'验证在线证书状态',
        'ocspUri'=> '校验地址',
        'OCSPResponseStatus'=>'在线证书状态响应状态',
        'certificateStatus'=>'服务器证书状态',
        //'thisUpdate'=>'有效日期',
        //'nextUpdate'=>'失效日期',
        'CN'=>'通用名',
        'C'=>'国家',
        'O'=>'组织',
        'OU'=>'组织单元',
        'L'=>'城市',
        'ST'=>'省份',
        'street'=>'街道',
        'jurisdictionC'=>'国家',
        'jurisdictionO'=>'组织',
        'jurisdictionL'=>'城市',
        'jurisdictionST'=>'省份',
        'postalCode'=>'邮编',
        'serialNumber'=>'序号',
        'businessCategory'=>'企业性质',
    ];
    public static function t($key)
    {
        if(empty(self::$dict[$key])) {
            return $key;
        }
        return self::$dict[$key];
    }

    public function escapeShellPath($path)
    {
        return str_replace('\\','/',$path);
    }

    /**
     * @param $uri
     * @param $file
     * @return bool
     */
    public function saveRemoteFile($uri, $file)
    {
        $ch = curl_init(($uri));
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $rst = curl_exec($ch);
        curl_close($ch);
        if ($rst) {
            file_put_contents($file,$rst);
            return true;
        }
        return false;
    }


    /**
     * @param $string
     * @return bool|string
     */
    protected function findRootCACert($string){
        $string = str_replace(' ','',$string);
        $targetDir = __DIR__ . '/certs/';
        $file = $this->escapeShellPath($targetDir. $string . '.crt');
        $name =  md5($string);
        $md5file = $this->escapeShellPath($this->rootCADir. $name . '.crt');
        if (file_exists($md5file)) {
            return $md5file;
        } else if (file_exists($file)) {
            return $file;
        }
        return false;
    }

    public function getRootCAFile($issuer){
        $caFile = null;
        if (isset($issuer['CN'])) {
            if ($caFile = $this->findRootCACert($issuer['CN'])) {
                return $caFile;
            }
        }
        if (isset($issuer['OU'])) {
            if ($caFile = $this->findRootCACert($issuer['OU'])) {
                return $caFile;
            }
        }
        if (isset($issuer['O'])) {
            if ($caFile = $this->findRootCACert($issuer['O'])) {
                return $caFile;
            }
        }
        return $caFile;
    }

    public function caIssuersToChain($file)
    {
        return "-----BEGIN CERTIFICATE-----\n"
        . wordwrap(base64_encode(file_get_contents($file)), 65, "\n", 1)
        . "\n-----END CERTIFICATE-----";
    }

    /**
     * @param $chain
     * @return string
     */
    public function convert2pem($chain) {
        $pem = '';
        openssl_x509_export($chain,$pem);
        return $pem;
    }


    /**
     * @param $dir string
     * @return string
     */
    public function getDirPath($dir){
        $dir = $this->dataDir . DIRECTORY_SEPARATOR . trim($dir,'/\\');
        if (!is_dir($dir)) {
            mkdir($dir,0777,true);
        }
        return $dir . DIRECTORY_SEPARATOR;
    }

    /**
     * @param $file string
     * @return bool
     */
    public function invalidFile($file)
    {
        $invalid = !file_exists($file) || $this->timestamp -filemtime($file) > $this->fileMaxSaveDays * 84600;
        if ($invalid) {
            @unlink($file);
        }
        return $invalid;
    }

    /**
     * @param $file string  sould be at least +100KB.
     * @return bool
     */
    public function isNormalCertificateFile($file)
    {
        if(stat($file)['size'] < 10 ) {
            @unlink($file);
            return false;
        }
        return false;
    }

    public function uuid() {
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

    public static function fileNameToMD5($distDir) {
        if (!is_dir($distDir)) {
            mkdir($distDir,0777,true);
        }
        $targetDir = __DIR__ . '/certs/';
        if (is_dir($targetDir)){
            if ($dh = opendir($targetDir)){
                $fh = fopen($distDir .'/md5.txt','wb');
                while (($file = readdir($dh)) !== false){
                    $name = basename($file,'.crt');
                    $name = mb_convert_encoding($name,'UTF-8','GBK');
                    $hash =  md5($name);
                    echo "filename:" . $name . ":".$hash."<br>";
                    fwrite($fh,$hash . ':' . $name . ".crt\n");
                    copy($targetDir . $file,$distDir . $hash.'.crt');
                }
                fclose($fh);
                closedir($dh);
            }
        }
    }

}