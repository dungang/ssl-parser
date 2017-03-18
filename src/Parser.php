<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 15:40
 */

namespace dungang\sslparser;


class Parser
{

    public $host = 'localhost';

    public $port = '443';

    public $ip;

    public $timeout = 30;

    public $maxChainLength = 10;

    /**
     * @var string  指定 CAFile的路径。所有CA根
     */
    public $rootCAFile;

    public  $rootCaDir;

    /**
     * @var string 临时目录
     */
    public $tmpPath;

    /**
     * @var string
     * blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
     * create the blacklist:
     * https://packages.debian.org/source/squeeze/openssl-blacklist
     * svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
     * find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
     * sort -u unsorted_blacklist.db > debian_blacklist.db
     *
     */
    public $debianBlacklistDbFile;


    /**
     * @var array
     * 2015-09-21 http://www.certificate-transparency.org/known-logs
     * $ct_urls = ["https://ct.ws.symantec.com",
     *         "https://ct.googleapis.com/pilot",
     *         "https://ct.googleapis.com/aviator",
     *         "https://ct.googleapis.com/rocketeer",
     *         "https://ct1.digicert-ct.com/log",
     *         "https://ct.izenpe.com",
     *         "https://ctlog.api.venafi.com",
     *         "https://log.certly.io"];
     *
     */
    public $ctUrls = ["https://ct.googleapis.com/aviator"];

    # 2014-11-10 (nov) from wikipedia
    public $evOids = [
        "1.3.6.1.4.1.34697.2.1",
        "1.3.6.1.4.1.34697.2.2",
        "1.3.6.1.4.1.34697.2.3",
        "1.3.6.1.4.1.34697.2.4",
        "1.2.40.0.17.1.22",
        "2.16.578.1.26.1.3.3",
        "1.3.6.1.4.1.17326.10.14.2.1.2",
        "1.3.6.1.4.1.17326.10.8.12.1.2",
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        "2.16.840.1.114412.2.1",
        "2.16.840.1.114412.1.3.0.2",
        "2.16.528.1.1001.1.1.1.12.6.1.1.1",
        "2.16.840.1.114028.10.1.2", "0.4.0.2042.1.4",
        "0.4.0.2042.1.5",
        "1.3.6.1.4.1.13177.10.1.3.10",
        "1.3.6.1.4.1.14370.1.6",
        "1.3.6.1.4.1.4146.1.1",
        "2.16.840.1.114413.1.7.23.3",
        "1.3.6.1.4.1.14777.6.1.1",
        "2.16.792.1.2.1.1.5.7.1.9",
        "1.3.6.1.4.1.22234.2.5.2.3.1",
        "1.3.6.1.4.1.782.1.2.1.8.1",
        "1.3.6.1.4.1.8024.0.2.100.1.2",
        "1.2.392.200091.100.721.1",
        "2.16.840.1.114414.1.7.23.3",
        "1.3.6.1.4.1.23223.2",
        "1.3.6.1.4.1.23223.1.1.1",
        "2.16.756.1.83.21.0",
        "2.16.756.1.89.1.2.1.1",
        "2.16.840.1.113733.1.7.48.1",
        "2.16.840.1.114404.1.1.2.4.1",
        "2.16.840.1.113733.1.7.23.6",
        "1.3.6.1.4.1.6334.1.100.1",
        "2.16.840.1.114171.500.9",
        "1.3.6.1.4.1.36305.2"];


    protected $dsn;

    protected $sslStream;

    protected $streamData;

    protected $streamParams;

    protected $canExeShell = false;

    protected $warnings = [];

    protected $uuid;

    protected $supportedCipherSuitesCount = 0;

    public function  __construct($host,$ip,$port=443) {
        $this->host = $host;
        $this->port = $port;
        $this->ip = $ip;
        $this->dsn = 'ssl://' . $host . ':' . $port;
        $this->uuid = $this->genUuid();

        if (function_exists('shell_exec')) {
            $this->canExeShell = $this->checkOpensslInstalled();
        }

        if(empty($this->rootCAFile)) {
            $this->rootCAFile = __DIR__ . DIRECTORY_SEPARATOR . 'cacert.pem';
        }

        if (empty($this->rootCaDir)) {
            $this->rootCaDir = __DIR__ . DIRECTORY_SEPARATOR . 'certs';
        }

        if(empty($this->debianBlacklistDbFile)) {
            $this->debianBlacklistDbFile = __DIR__ . DIRECTORY_SEPARATOR . 'debian_blacklist.db';
        }

    }

    public function parser() {

        $this->streamData = $this->getStreamData();
        $this->streamParams =  stream_context_get_params($this->streamData);
        $options = $this->streamParams['options']['ssl'];
        $certificateChains =  $this->parseChains($options['peer_certificate_chain']);
        $length = count($certificateChains);
        foreach($certificateChains as $idx => $chain){
            $chainKey = $idx+1;
            if ($idx == $length -1 ) {
                $chainKey = $idx;
            }
            $chainKey = sprintf('%s',$chainKey) ;
            if ($idx == 0) {
                $data['connection'] = $this->getConnectionMetaInfo($this->ip,$certificateChains);
                $data['chain'][$idx] = $this->parseCertificateByShell($certificateChains, $idx, $chainKey, $this->host, true, $this->port, false);
            } else {
                $data['chain'][$idx] = $this->parseCertificateByShell($certificateChains,$idx, $chainKey, null, false, $this->port, false);
            }
        }


//        $data['certificateTransparency'] = [];
//
//        foreach ($this->ctUrls as $ctUrl) {
//            $submitToCT = $this->submitCertToCT($data["chain"], $ctUrl);
//            $ctResult = json_decode($submitToCT, TRUE);
//            if ($ctResult === null
//                && json_last_error() !== JSON_ERROR_NONE) {
//                $resultCt = array('result' => $submitToCT);
//                $data["certificate_transparency"][$ctUrl] = $resultCt;
//            } else {
//                $data["certificate_transparency"][$ctUrl] = $ctResult;
//            }
//        }
        return $data;
    }

    public function checkOpensslInstalled()
    {
        $output = $error = 0;
        exec('openssl version -noout',$output,$error);
        if ($error == 1) {
            return false;
        }
        return true;
    }

    public function parseChains($chains)
    {
        $chainCertificates = [];
        foreach($chains as $key => $chain){
            $chainCertificates[$key]['source'] = openssl_x509_parse($chain);
            openssl_x509_export($chain,$chainCertificates[$key]['pem']);
            $chainCertificates[$key]['resource'] = $chain;
            $chainCertificates[$key]['key'] = $key;

        }
        return $chainCertificates;
    }


    public function getConnectionMetaInfo($ip,$chainCertificates)
    {
        $pems = [];
        $sources = [];
        foreach($chainCertificates as $key => $certificate){
            $pems[$key]= $certificate['pem'];
            $sources[$key]= $certificate['source'];
        }
        return [
            'checkedHost'=> $this->host,
            //'validateChain'=> $this->validateCertificatePemChainsByShell($pems),
            'constructChain'=> $this->chainConstruction($sources[0],$pems[0]),
            'validateHostIp'=> $this->validateHostIp($ip),
            'connectionCompression'=>$this->connectionCompressionByShell($ip),
            //'validateSupportedProtocols'=>$this->testSslConnectionProtocolsByShell($ip),
            'supportedCipherSuites'=>$this->getSupportedCipherSuites($ip),
            //'tlsFallbackSCSV'=>$this->testTLSFallbackSCSVByShell($ip),
            'headers'=>$this->parserHeaders($ip),
            //'hearbeat'=>$this->testHeartbeatByShell(),
        ];
    }

    public function submitCertToCT($chain, $ct_url) {
        $ct_chain = array('chain' => []);
        foreach ($chain as $key => $value) {
            $string = $value['key']['certificatePem'];
            $pattern = '/-----(.*)-----/';
            $replacement = '';
            $string = preg_replace($pattern, $replacement, $string);
            $pattern = '/\n/';
            $replacement = '';
            $string = preg_replace($pattern, $replacement, $string);
            array_push($ct_chain['chain'], $string);
        }
        $post_data = json_encode($ct_chain);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $ct_url . "/ct/v1/add-chain");
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FAILONERROR, false);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_POST, count($post_data));
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        $ct_output = curl_exec($ch);
        curl_close($ch);
        return $ct_output;
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

    public function validateHostIp($ip)
    {
        $result["ip"] = $ip;
        if (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 )) {
            $addr = inet_pton(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
            $unpack = unpack('H*hex', $addr);
            $hex = $unpack['hex'];
            $arpa = implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
            if (!empty(dns_get_record($arpa, DNS_PTR)[0]["target"])) {
                $result["hostname"] = dns_get_record($arpa, DNS_PTR)[0]["target"];
            } else {
                $result["hostname"] = "$this->host (No PTR available).";
            }
        } elseif (filter_var(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 )) {
            $cleanIp = preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip);
            $realIp = gethostbyaddr($cleanIp);
            if (!empty($realIp)) {
                $result["hostname"] = gethostbyaddr(preg_replace('/[^A-Za-z0-9\.\:-]/', '', $ip));
            } else {
                $result["hostname"] = "$this->host (No PTR available).";
            }
        } else {
            $result["hostname"] = "$this->host (No PTR available).";
        }
        return $result;
    }

    public function connectionCompressionByShell($ip) {
        if (!$this->canExeShell) {
            return null;
        }
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        //if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
        //  return true;
        //}
        $exitStatus = 0;
        $output = 0;
        $cmd = 'echo | timeout %d openssl s_client -servername %s -connect %s:%s -status -tlsextdebug 2>&1 | grep -qe "^Compression: NONE"';
        exec(sprintf($cmd,$this->timeout,escapeshellcmd($this->host),$this->escapeShellIp($ip),escapeshellcmd($this->port)),$output, $exitStatus);
        if ($exitStatus == 0) {
            return false;
        } else {
            $this->warnings[] = 'SSL compression enabled. Please disable to prevent attacks like CRIME.';
            // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
            // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            //   // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
            //   $result["warning"][] = 'SSL compression not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
            // } else {
            return true;
            // }

        }
    }

    public function testSslV2ByShell($ip) {
        if (!$this->canExeShell) {
            return null;
        }
        $exitStatus = 0;
        $output = 0;
        exec('echo | timeout ' . $this->timeout
            . ' openssl s_client -connect "' . escapeshellcmd($ip) . ':' . escapeshellcmd($this->port)
            . '" -ssl2 2>&1 >/dev/null', $output, $exitStatus);
        if ($exitStatus == 0) {
            return true;
        } else {
            return false;
        }
    }

    public function testSSLProtocolWithoutV2($ip,$schema,$method)
    {
        $stream = stream_context_create (array("ssl" =>
            array("verify_peer" => false,
                "capture_session_meta" => true,
                "verify_peer_name" => false,
                "peer_name" => $this->host,
                "allow_self_signed" => true,
                'crypto_method' => $method,
                "sni_enabled" => true)));
        $read = stream_socket_client("$schema://$ip:$this->port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
        return $read === false ? false: true;
    }

    public function testSslConnectionProtocolsByShell($ip) {
        $old_error_reporting = error_reporting();
        error_reporting(0);
        $results = [
            'sslv2'=>$this->testSslV2ByShell($ip),
            'sslv3'=>$this->testSSLProtocolWithoutV2($ip,'sslv3',STREAM_CRYPTO_METHOD_SSLv3_CLIENT),
            'tlsv1.0'=>$this->testSSLProtocolWithoutV2($ip,'tlsv1.0',STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT),
            'tlsv1.1'=>$this->testSSLProtocolWithoutV2($ip,'tlsv1.1',STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT),
            'tlsv1.2'=>$this->testSSLProtocolWithoutV2($ip,'tlsv1.2',STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT),
        ];
        error_reporting($old_error_reporting);
        foreach ($results as $key => $value) {
            if ( $value == true ) {
                if ( $key == "sslv2") {
                    $this->warnings[] = 'SSLv2 supported. Please disable ASAP and upgrade to a newer protocol like TLSv1.2.';
                }
                if ( $key == "sslv3") {
                    $this->warnings[] = 'SSLv3 supported. Please disable and upgrade to a newer protocol like TLSv1.2.';
                }
            } else {
                if ( $key == "tlsv1.2") {
                    $this->warnings[] = 'TLSv1.2 unsupported. Please enable TLSv1.2.';
                }
            }
        }
        return $results;
    }

    public function getSupportedCipherSuites($ip) {
        $old_error_reporting = error_reporting();
        error_reporting(0);
        $CipherSuites = array('ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES256-SHA384',
            'ECDHE-RSA-AES256-SHA',
            'ECDHE-ECDSA-AES256-SHA',
            'SRP-DSS-AES-256-CBC-SHA',
            'SRP-RSA-AES-256-CBC-SHA',
            'SRP-AES-256-CBC-SHA',
            'DH-DSS-AES256-GCM-SHA384',
            'DHE-DSS-AES256-GCM-SHA384',
            'DH-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES256-SHA256',
            'DHE-DSS-AES256-SHA256',
            'DH-RSA-AES256-SHA256',
            'DH-DSS-AES256-SHA256',
            'DHE-RSA-AES256-SHA',
            'DHE-DSS-AES256-SHA',
            'DH-RSA-AES256-SHA',
            'DH-DSS-AES256-SHA',
            'DHE-RSA-CAMELLIA256-SHA',
            'DHE-DSS-CAMELLIA256-SHA',
            'DH-RSA-CAMELLIA256-SHA',
            'DH-DSS-CAMELLIA256-SHA',
            'ECDH-RSA-AES256-GCM-SHA384',
            'ECDH-ECDSA-AES256-GCM-SHA384',
            'ECDH-RSA-AES256-SHA384',
            'ECDH-ECDSA-AES256-SHA384',
            'ECDH-RSA-AES256-SHA',
            'ECDH-ECDSA-AES256-SHA',
            'AES256-GCM-SHA384',
            'AES256-SHA256',
            'AES256-SHA',
            'CAMELLIA256-SHA',
            'PSK-AES256-CBC-SHA',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES128-SHA256',
            'ECDHE-RSA-AES128-SHA',
            'ECDHE-ECDSA-AES128-SHA',
            'SRP-DSS-AES-128-CBC-SHA',
            'SRP-RSA-AES-128-CBC-SHA',
            'SRP-AES-128-CBC-SHA',
            'DH-DSS-AES128-GCM-SHA256',
            'DHE-DSS-AES128-GCM-SHA256',
            'DH-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES128-SHA256',
            'DHE-DSS-AES128-SHA256',
            'DH-RSA-AES128-SHA256',
            'DH-DSS-AES128-SHA256',
            'DHE-RSA-AES128-SHA',
            'DHE-DSS-AES128-SHA',
            'DH-RSA-AES128-SHA',
            'DH-DSS-AES128-SHA',
            'DHE-RSA-SEED-SHA',
            'DHE-DSS-SEED-SHA',
            'DH-RSA-SEED-SHA',
            'DH-DSS-SEED-SHA',
            'DHE-RSA-CAMELLIA128-SHA',
            'DHE-DSS-CAMELLIA128-SHA',
            'DH-RSA-CAMELLIA128-SHA',
            'DH-DSS-CAMELLIA128-SHA',
            'ECDH-RSA-AES128-GCM-SHA256',
            'ECDH-ECDSA-AES128-GCM-SHA256',
            'ECDH-RSA-AES128-SHA256',
            'ECDH-ECDSA-AES128-SHA256',
            'ECDH-RSA-AES128-SHA',
            'ECDH-ECDSA-AES128-SHA',
            'AES128-GCM-SHA256',
            'AES128-SHA256',
            'AES128-SHA',
            'SEED-SHA',
            'CAMELLIA128-SHA',
            'IDEA-CBC-SHA',
            'PSK-AES128-CBC-SHA',
            'ECDHE-RSA-RC4-SHA',
            'ECDHE-ECDSA-RC4-SHA',
            'ECDH-RSA-RC4-SHA',
            'ECDH-ECDSA-RC4-SHA',
            'RC4-SHA',
            'RC4-MD5',
            'PSK-RC4-SHA',
            'ECDHE-RSA-DES-CBC3-SHA',
            'ECDHE-ECDSA-DES-CBC3-SHA',
            'SRP-DSS-3DES-EDE-CBC-SHA',
            'SRP-RSA-3DES-EDE-CBC-SHA',
            'SRP-3DES-EDE-CBC-SHA',
            'EDH-RSA-DES-CBC3-SHA',
            'EDH-DSS-DES-CBC3-SHA',
            'DH-RSA-DES-CBC3-SHA',
            'DH-DSS-DES-CBC3-SHA',
            'ECDH-RSA-DES-CBC3-SHA',
            'ECDH-ECDSA-DES-CBC3-SHA',
            'DES-CBC3-SHA',
            'PSK-3DES-EDE-CBC-SHA',
            'EDH-RSA-DES-CBC-SHA',
            'EDH-DSS-DES-CBC-SHA',
            'DH-RSA-DES-CBC-SHA',
            'DH-DSS-DES-CBC-SHA',
            'DES-CBC-SHA',
            'EXP-EDH-RSA-DES-CBC-SHA',
            'EXP-EDH-DSS-DES-CBC-SHA',
            'EXP-DH-RSA-DES-CBC-SHA',
            'EXP-DH-DSS-DES-CBC-SHA',
            'EXP-DES-CBC-SHA',
            'EXP-RC2-CBC-MD5',
            'EXP-RC4-MD5',
            'ECDHE-RSA-NULL-SHA',
            'ECDHE-ECDSA-NULL-SHA',
            'AECDH-NULL-SHA',
            'ECDH-RSA-NULL-SHA',
            'ECDH-ECDSA-NULL-SHA',
            'NULL-SHA256',
            'NULL-SHA',
            'NULL-MD5');
        $results = array();
        foreach ($CipherSuites as $value) {
            $results[$value] = false;
            $stream = stream_context_create (array("ssl" =>
                array("verify_peer" => false,
                    "verify_peer_name" => false,
                    "allow_self_signed" => true,
                    "peer_name" => $this->host,
                    'ciphers' => $value,
                    "sni_enabled" => true)));
            $read_stream = stream_socket_client("ssl://$ip:$this->port", $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $stream);
            if ( $read_stream !== false ) {
                $results[] = $value;
            }
        }
        error_reporting($old_error_reporting);
        $this->supportedCipherSuitesCount = count($results);
        return $results;
    }


    public function testTLSFallbackSCSVByShell($ip)
    {
        if (!$this->canExeShell) {
            return null;
        }
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        //     // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
        //     return false;
        // }
        $status = false;
        if ($this->supportedCipherSuitesCount > 1) {
            // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
            $cmd = 'echo | timeout $timeout openssl s_client -servername %s -connect %s:%s -fallback_scsv -no_tls1_2 2>&1 >/dev/null';
            $fallback_test = shell_exec(sprintf($cmd,$this->timeout,escapeshellcmd($this->host),$this->escapeShellIp($ip),$this->port));
            if ( stripos($fallback_test, "SSL alert number 86") !== false ) {
                $status = true;
            }
        }
        if ($status && $this->supportedCipherSuitesCount == 1) {
            $rst = "Only 1 protocol enabled, fallback not possible, TLS_FALLBACK_SCSV not required.";
        } else if ($status && $this->supportedCipherSuitesCount > 1) {
                $rst = "supported";
        } else {
            $rst = "unsupported";
            $this->warnings[] = "TLS_FALLBACK_SCSV unsupported. Please upgrade OpenSSL to enable. This offers downgrade attack protection.";
        }
        return $rst;
    }

    public function parserHeaders($ip)
    {
        // first check if server is http. otherwise long timeout.
        // sometimes fails cloudflare with
        // error:14077438:SSL routines:SSL23_GET_SERVER_HELLO:tlsv1 alert internal error
        $headers = [];
        $ch = curl_init(("https://" . $ip . ":" . $this->port));
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Host: $this->host"));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
        if(curl_exec($ch) !== false ||  curl_errno($ch) == 35) {
            stream_context_set_default(
                array("ssl" =>
                    array("verify_peer" => false,
                        "capture_session_meta" => true,
                        "verify_peer_name" => false,
                        "peer_name" => $this->host,
                        "allow_self_signed" => true,
                        "sni_enabled" => true),
                    'http' => array(
                        'method' => 'GET',
                        'max_redirects' => 1,
                        'header' => 'Host: '.$this->host,
                        'timeout' => $this->timeout
                    )
                )
            );
            $headers = get_headers("https://$ip:$this->port", 1);
            if (!empty($headers)) {
                $headers = array_change_key_case($headers, CASE_LOWER);
            }
        }
        curl_close($ch);

        if (isset($headers["strict-transport-security"])) {
            if ( is_array($headers["strict-transport-security"])) {
                $result["strict_sransport-security"] = substr($headers["strict-transport-security"][0], 0, 50);
            } else {
                $result["strict_transport_security"] = substr($headers["strict-transport-security"], 0, 50);
            }
        } else {
            $result["strict_transport_security"] = 'not set';
            $this->warnings[] = "HTTP Strict Transport Security not set.";
        }
        //hpkp
        if ( isset($headers["public-key-pins"])) {
            if ( is_array($headers["public-key-pins"])) {
                $result["public_key_pins"] = substr($headers["public-key-pins"][0], 0, 255);
            } else {
                $result["public_key_pins"] = substr($headers["public-key-pins"], 0, 255);
            }
        } else {
            $result["public_key_pins"] = 'not set';
        }
        if ( isset($headers["public-key-pins-report-only"])) {
            if ( is_array($headers["public-key-pins-report-only"])) {
                $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"][0], 0, 255);
            } else {
                $result["public_key_pins_report_only"] = substr($headers["public-key-pins-report-only"], 0, 255);
            }
        }
        return $result;
    }


    public function staplingOCSPByShell($ip)
    {
        if (!$this->canExeShell) {
            return null;
        }
        // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
        // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        //       // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
        //   return false;
        // }
        $stapling = [];
        // escapeshellcmd adds \[\] to ipv6 address.
        // todo: look into escapeshellarg vs. escapeshellcmd
        $cmd = 'echo | timeout %d openssl s_client -servername %s -connect %s:%d -tlsextdebug -status 2>&1 | sed -n "/OCSP response:/,/---/p"';
        $output = shell_exec(sprintf($cmd,$this->timeout,escapeshellcmd($this->host),$this->escapeShellIp($ip),escapeshellcmd($this->port)));
        if (strpos($output, "no response sent") !== false) {
            $stapling = array("working" => 0,
                "cert_status" => "No response sent");
        }
        if (strpos($output, "OCSP Response Data:") !== false) {
            $lines = array();
            $output = preg_replace("/[[:blank:]]+/"," ", $output);
            $stapling_status_lines = explode("\n", $output);
            $stapling_status_lines = array_map('trim', $stapling_status_lines);
            foreach($stapling_status_lines as $line) {
                if($this->endsWith($line, ":") == false) {
                    list($k, $v) = explode(":", $line);
                    $lines[trim($k)] = trim($v);
                }
            }
            $stapling = array("working" => 1,
                "cert_status" => $lines["Cert Status"],
                "this_update" => $lines["This Update"],
                "next_update" => $lines["Next Update"],
                "responder_id" => $lines["Responder Id"],
                "hash_algorithm" => $lines["Hash Algorithm"],
                "signatureAlgorithm" => $lines["Signature Algorithm"],
                "issuer_name_hash" => $lines["Issuer Name Hash"]);
        }
        if($stapling["working"] == 1) {
            $result = $stapling;
        } else {
            // OpenSSL 1.1.0 has ipv6 support: https://rt.openssl.org/Ticket/Display.html?id=1832
            // if (filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            //   // ipv6 openssl tools are broken. (https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest)
            //   $result["warning"][] = 'OCSP Stapling not tested because of <a href="https://rt.openssl.org/Ticket/Display.html?id=1365&user=guest&pass=guest">bugs</a> in the OpenSSL tools and IPv6.';
            // } else {
            $result = "not set";
            $this->warnings[] = "OCSP Stapling not enabled.";
            // }
        }
        return $result;
    }
    
    public function pythonTestHeartBleedByShell($ip, $port) {
        if (!$this->canExeShell) {
            return null;
        }
        //this uses an external python2 check to test for the heartblead vulnerability
        $exitStatus = 0;
        $output = 0;
        $cmdExitStatus = 0;
        $cmdOutput = 0;
        $result = 0;
        $uuid = $this->uuid;
        $heartDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'heart';
        $this->mkdir($heartDir);
        $tmpFile = $heartDir . DIRECTORY_SEPARATOR . $uuid . ".txt";
        # check if python2 is available
        exec("command -v python2 >/dev/null 2>&1", $cmdOutput, $cmdExitStatus);
        if ($cmdExitStatus != 1) {
            //15 is a reasonable timeout. 
            exec("timeout 15 python2 " . __DIR__ . "/pythonheartbleed.py " . escapeshellcmd($ip) . " --json \"" . $tmpFile . "\" --threads 1 --port " . escapeshellcmd($port) . " --silent", $output, $exitStatus);
            if (file_exists($tmpFile)) {
                $json_data = json_decode(file_get_contents($tmpFile),true);
                foreach ($json_data as $key => $value) {
                    if ($value['status'] == true) {
                        $result = "vulnerable";
                    } else {
                        $result = "not_vulnerable";
                    }
                }
                @unlink($tmpFile);
            }
        } else {
            $result = "python2error";
        }
        return $result;
    }

    public function testHeartbeatByShell() {
        if (!$this->canExeShell) {
            return null;
        }
        //this tests for the heartbeat protocol extension
        $result = false;
        $cmd = 'echo | timeout %s openssl s_client -connect $s:%d -servername %s -tlsextdebug 2>&1 </dev/null | awk -F\" \'/server extension/ {print $2}\'';
        $output = shell_exec(sprintf($cmd,$this->timeout,escapeshellcmd($this->host),escapeshellcmd($this->port)));
        $output = preg_replace("/[[:blank:]]+/"," ", $output);
        $output = explode("\n", $output);
        $output = array_map('trim', $output);
        if ( in_array("heartbeat", $output) ) {
            $result = true;
        }
        return $result;
    }

    protected function endsWith($haystack, $needle) {
      // search forward starting from end minus needle length characters
      if(!empty($haystack)) {
        return $needle === "" || strpos($haystack, $needle, strlen($haystack) - strlen($needle)) !== FALSE;
      }
      return false;
    }

    protected function escapeShellIp($ip)
    {
        if (!filter_var(preg_replace('/[^A-Za-z0-9\.\:_-]/', '', $ip), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip = escapeshellcmd($ip);
        }
        return $ip;
    }


    public function validateCertificatePemChainsByShell($pemChains)
    {
        if (!$this->canExeShell) {
            return null;
        }
        $result = ['status'=>'failed'];
        $file = $this->tmpPath .DIRECTORY_SEPARATOR . 'peer-certificate-chains-' . $this->uuid. '.pem';
        file_put_contents($file,trim(implode("\n", array_reverse($pemChains))));
        $cmd = sprintf("openssl verify -verbose -purpose any -CAfile %s  %s",$this->rootCAFile, $file);
        exec(escapeshellcmd(str_replace('\\','/',$cmd)),$output,$error);
        if ($error != 1 or !preg_match('/OK/',$output)) {
            $result['status'] = 'failed';
            $result['error'] = 'Error: Validating certificate chain failed:'. str_replace($file, '', implode("\n", $output));
            $this->warnings[] = 'Validating certificate chain failed. Probably non-trusted root/self signed certificate, or the chain order is wrong.';
        } else {
            $result['status'] = 'success';
        }
        @unlink($file);
        return $result;
    }


    public function chainConstruction($source,$pem)
    {
        $newChains = [];
        $newChains[] = $this->constructChain($source,$pem);
        //if (count($sources) <= $this->maxChainLength) {
            $issuerChain = $this->getCertificateIssuerChain($source);
            if (count($issuerChain['certs']) >=1 ) {
                $issuerCrts = array_unique($issuerChain['certs']);
                foreach($issuerCrts as $value) {
                    $newChains[] = $value;
                }
            }
        //}
        $newChains = array_unique($newChains);
        $crtFullSubjects = [];
        foreach($newChains as $idx => $newChain) {
            $newSource = openssl_x509_parse($newChain);
            $crtFullSubjects[] = [
                'cn'=>$this->formatSubject($newSource['subject']),
                'issuer'=>$this->formatSubject($newSource['issuer'])
            ];
        }
        return [
            'fullSubjects'=>$crtFullSubjects,
            'correctChains'=>$newChains
        ];
    }

    public function getCertificateIssuerChain($firstChainSource,$number=1,$result=null)
    {
        if ($result['complete'] == 'yes') {
            return $result;
        }
        if ($number > $this->maxChainLength) {
            $result['complete'] = 'error';
            return $result;
        }
        $number += 1;

        if (!is_array($result)) {
            $result = ['certs' => array(), 'complete' => 'false'];
        }
        $fullSubject = $this->formatSubject($firstChainSource['subject']);
        $fullIssuer = $this->formatSubject($firstChainSource['issuer']);
        if ($fullSubject == $fullIssuer) {
            $result['complete'] = "yes";
            return $result;
        }
        $issuer = $this->getCertificateIssuerCrt($firstChainSource);
        if ($issuer) {
            $result['certs'][] = $issuer;
            $issuerSource = openssl_x509_parse($issuer);
            $result = $this->getCertificateIssuerChain($issuerSource,$number,$result);
            return $result;
        } else {
            return $result;
        }
    }


    public function getCertificateIssuerCrt($chainSource)
    {
        $crtHashDir = $this->tmpPath . DIRECTORY_SEPARATOR . "crt_hash";
        $this->mkdir($crtHashDir);
        $crtCheckHash = $this->formatSubject($chainSource["issuer"]);
        $hashFile = $crtHashDir . $crtCheckHash . ".pem";
        $crtData = null;
        if (!file_exists($hashFile)) {
            $uris = $this->parseAuthorityInfoAccess($chainSource);
            if(is_array($uris)) {
                if (isset($uris['CA Issuers'])) {
                    $url = trim($uris['CA Issuers']);
                    $crtHash = hash("sha256",$url);
                    $crtHashDerFile = $crtHashDir . DIRECTORY_SEPARATOR . $crtHash . ".der";
                    if ($this->fileExpired($crtHashDerFile)) {
                        $this->saveRemoteFile($url,$crtHashDerFile);
                        $this->checkCertificateFileSize($crtHashDerFile);
                    }
                    if (file_exists($crtHashDerFile)) {
                        //we have a a der file, we need to convert it to pem and return it.
                        //dirty way to get pem from der...
                        $crtData =
                            "-----BEGIN CERTIFICATE-----\n"
                            . wordwrap(base64_encode(file_get_contents($crtHashDerFile)), 65, "\n", 1)
                            . "\n-----END CERTIFICATE-----";

                        $crtSource = openssl_x509_parse($crtData);
                        $crtPem = "";
                        openssl_x509_export($crtData,$crtPem);
                        $crtHash = hash("sha256",$this->formatSubject($crtSource['subject']));
                        $crtHashFile = $crtHashDir . DIRECTORY_SEPARATOR . $crtHash . ".pem";
                        if ($this->fileExpired($crtHashFile)) {
                            file_put_contents($crtHashFile,trim($crtPem));
                        }
                        $this->checkCertificateFileSize($crtHashFile);
                        return $this->constructChain($crtSource,$crtPem);
                    }
                }
            }
        } else {
            $crtData = file_get_contents($hashFile);
            $hashPem = "";
            openssl_x509_export($crtData,$hashPem);
            if ($hashPem) {
                $hashSource = openssl_x509_parse($crtData);
                return $this->constructChain($hashSource,$hashPem);
            }
        }
        return null;
    }

    public function parseAuthorityInfoAccess($source)
    {
        $uris = [];
        if (isset($source['extensions']['authorityInfoAccess'])) {
            $access = $source['extensions']['authorityInfoAccess'];
            if (is_string($access) && preg_match_all('/(.*?)\s+\-\s+URI\:(.*)/m',$access,$matches)) {
                if (count($matches) == 3) {
                    foreach ($matches[1] as $key => $word) {
                        $uris[$word] = $matches[2][$key];
                    }
                }
            }
        }
        return $uris;
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

    public static function t($term)
    {
        return $term;
    }

    public function genUuid() {
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


    public function formatSubject($subject)
    {
        $issuerFull = '';
        asort($subject);
        foreach( $subject as $key=>$value) {
            $issuerFull = "/" . $key . "=" . $value . $issuerFull;
        }
        return hash("sha256",$issuerFull);
    }

    public function fileExpired($file,$day=5)
    {
        return !file_exists($file) || time()-filemtime($file) > $day * 84600;
    }

    public function checkCertificateFileSize($file)
    {
        if(stat($file)['size'] < 10 ) {
            //probably a corrypt file. sould be at least +100KB.
            @unlink($file);
        }
    }


    protected function mkdir($dir)
    {
        if (!is_dir($dir)) {
            mkdir($dir,true);
        }
    }

    protected function bcdechex($dec) {
        $hex = '';
        do {
            $last = bcmod($dec, 16);
            $hex = dechex($last).$hex;
            $dec = bcdiv(bcsub($dec, $last), 16);
        } while($dec>0);
        return $hex;
    }

    public function constructChain($source,$pem)
    {
        $crt_name = $source['name'];
        return "#start " . $crt_name . "\n" . $pem . "\n#end " . $crt_name . "\n";
    }

    public function certHash($hashAlg, $raw_cert_to_hash) {
        //returns the hash of the a certificate. Same as "openssl alg" cli.
        return hash($hashAlg, base64_decode($raw_cert_to_hash));
    }

    public function getSansFromCsrByShell($csr) {
        if (!$this->canExeShell) {
            return null;
        }
        //openssl_csr_get_subject doesn't support SAN names.
        $csrDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'csr';
        $this->mkdir($csrDir);
        $filename = $csrDir . DIRECTORY_SEPARATOR ."csr-" . $this->uuid . "-" . self::genUuid() . ".csr.pem";
        $write_csr = file_put_contents($filename, $csr);
        $openssl_csr_output = false;
        if($write_csr !== FALSE) {
            $openssl_csr_output = trim(
                shell_exec("timeout " . $this->timeout . " openssl req -noout -text -in " . $filename . " | grep -e 'DNS:' -e 'IP:'")
            );
        }
        unlink($filename);
        $sans = [];
        if($openssl_csr_output) {
            $sans = array();
            $csr_san_dns = explode("DNS:", $openssl_csr_output);
            $csr_san_ip = explode("IP:", $openssl_csr_output);
            if(count($csr_san_dns) > 1) {
                foreach ($csr_san_dns as $key => $value) {
                    if($value) {
                        $san = trim(str_replace(",", "", str_replace("DNS:", "", $value)));
                        array_push($sans, $san);
                    }
                }
            }
            if(count($csr_san_ip) > 1) {
                foreach ($csr_san_ip as $key => $value) {
                    if($value) {
                        $san = trim(str_replace(",", "", str_replace("IP:", "", $value)));
                        array_push($sans, $san);
                    }
                }
            }
        }
        if(count($sans) >= 1) {
            return $sans;
        }
        return false;
    }

    public function verifyCertIssuerBySubjectHashWithShell($chain, $nextChain) {
        if (!$this->canExeShell) {
            return null;
        }
        //checks if the issuer of given cert is the same as the subject of the other cert, thus validating if cert 1 was signed by cert 2.
        $subjectDir = $this->tmpPath . DIRECTORY_SEPARATOR . "subject";
        $this->mkdir($subjectDir);
        $clientPem = $subjectDir . DIRECTORY_SEPARATOR . $this->uuid . '.cert_client.pem';
        $issuerPem = $subjectDir . DIRECTORY_SEPARATOR . $this->uuid . '.cert_issuer.pem';
        file_put_contents($clientPem,$chain['pem']);
        file_put_contents($issuerPem,$nextChain['pem']);
        $cmd = 'timeout %s openssl x509 -noout -issuer_hash -in %s 2>&1';
        $clientSubjectHash = shell_exec(sprintf($cmd,$this->timeout,$clientPem));
        $issuerSubjectHash = shell_exec(sprintf($cmd,$this->timeout,$issuerPem));
        //remove those temp files.
        @unlink($clientPem);
        @unlink($issuerPem);
        if ( $clientSubjectHash == $issuerSubjectHash ) {
            return true;
        } else {
            return false;
        }
    }

    public function saveRemoteFile($uri,$file)
    {
        $fp = fopen ($file, 'wb');
        $ch = curl_init(($uri));
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->timeout);
        curl_setopt($ch, CURLOPT_FILE, $fp);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_FRESH_CONNECT, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        if(curl_exec($ch) === false) {
            return [
                'status'=>false,
                'message'=>'Curl error: ' . htmlspecialchars(curl_error($ch))
            ];
        }
        curl_close($ch);
        fclose($fp);
        return [
            'status' => true,
        ];
    }

    public function crlVerifyByShell($source)
    {
        if (!$this->canExeShell) {
            return null;
        }
        $crlDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'crl';
        $this->mkdir($crlDir);
        $outs = ['Serial Number'=>strtoupper($this->bcdechex($source['serialNumber']))];
        if (isset($source['extensions']['crlDistributionPoints'])) {
            if (preg_match_all('/\s*URI\:(.*)/m',$source['extensions']['crlDistributionPoints'],$matches)) {
                $uri = null;
                if (count($matches) == 2) {
                    $uri = $matches[1][0];
                    $outs['uri'] = $uri;
                    $file = $crlDir . DIRECTORY_SEPARATOR . $this->uuid . ".crl";
                    $rst = $this->saveRemoteFile($uri,$file);
                    if ($rst['status']==true) {

                        if(stat($file)['size'] < 10 ) {
                            $outs["errorMessage"] = "crl could not be retreived";
                            return $outs;
                        }
                        $cmd = "timeout %d openssl crl -noout -text -inform der -in %s 2>&1";
                        $output = shell_exec(sprintf($cmd,$this->timeout,$file));
                        @unlink($file);

                        if(preg_match_all('/[ \t\f]*(.*?)\:[ \t\f]+(.*)$/xmD',$output,$matches)) {
                            if (count($matches) == 3) {
                                $revoked = false;
                                foreach($matches[1] as $k => $name) {
                                    if ($name == 'Serial Number') {
                                        if ($name == $outs['Serial Number']) {
                                            $revoked = true;
                                        }
                                    } else if ($name == 'Revocation Date') {
                                        if ($revoked) {
                                            $outs['Revocation Date'] = trim($matches[2][$k]);
                                        }
                                    } else {
                                        $outs[$name] = trim($matches[2][$k]);
                                    }
                                }
                                $outs['revoked'] = $revoked;
                                return $outs;
                            }
                        }
                    }
                }
            }
        }

        $outs['errorMessage'] = 'Not found crl uri';
        return $outs;
    }

    public function verifyCertificateHostname($source) {
        //validates hostname to check with hostnames in certificate CN or subjectAltNames
        if (isset($source['subject']['CN'])) {
            $cert_host_names = [];
            $cert_host_names[] = $source['subject']['CN'];
            if ($source['extensions']['subjectAltName']) {
                foreach ( explode("DNS:", $source['extensions']['subjectAltName']) as $altName ) {
                    foreach (explode(",", $altName) as $key => $value) {
                        $clearValue = str_replace(',', "", "$value");
                        if ( !empty($clearValue)) {
                            $cert_host_names[] = str_replace(" ", "", str_replace(',', "", "$value"));
                        }
                    }
                }
            }
            $hostFragment = explode(".", $this->host, 2);
            foreach ($cert_host_names as $key => $hostname) {
                if (strpos($hostname, "*.") === 0) {
                    // wildcard hostname from cert
                    $fragment = explode(".", $hostname, 2);
                    if (isset($hostFragment[1]) && isset($fragment[1]) && $hostFragment[1] == $fragment[1] ) {
                        // split cert name and host name on . and compare everything after the first dot
                        return true;
                    }
                }
                // no wildcard, just regular match
                if ($this->host == $hostname) {
                    return true;
                }
            }
        }
        // no match
        return false;
    }

    /**
     * @param $string
     * @return bool|string
     */
    protected function findRootCACert($string){
        $name =  str_replace(' ','',$string);
        $file = $this->rootCaDir .DIRECTORY_SEPARATOR . 'certs' . DIRECTORY_SEPARATOR . $name . '.crt';
        if (file_exists($file)) {
          return $file;
        }
        return false;
    }

    public function getRootCA($endInterChain){
        $issuer = $endInterChain['source']['issuer'];
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

    public function parseOCSPByShell($chains,$start=0)
    {
        if (!$this->canExeShell) {
            return null;
        }
        $result = [];
        $ocspDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'oscp';
        $this->mkdir($ocspDir);
        $source = $chains[$start]['source'];
        // ocsp
        if (isset($source['extensions']['authorityInfoAccess'])) {

            if ($uris = $this->parseAuthorityInfoAccess($source))
            {
                if (empty($uris['OCSP'])) {
                    $result["errorMessage"] = "No OCSP URI found in certificate";
                } else {
                    $length = count($chains);
                    $endChain = $chains[$length-1];
                    if ($caFile = $this->getRootCA($endChain)) {
                        $uri = $uris['OCSP'];
                        $chainsPem = [];
                        $interPem = [];
                        $sitePem = '';
                        foreach($chains as $i => $chain) {
                            if ($i == $start ) {
                                $sitePem = $chain['pem'];
                            } else if ($i > $start) {
                                $interPem[] = $chain['pem'];
                            }
                        }
                        if (isset($endChain['source']['issuer']['CN'])) {
                            $rootCN = str_replace(' ','',$endChain['source']['issuer']['CN']);
                            $rootPem = file_get_contents($this->rootCaDir . DIRECTORY_SEPARATOR . $rootCN . '.crt');
                            $chainsPem = $interPem;
                            $chainsPem[] = $rootPem;
                        }

                        $chainFile = $ocspDir . DIRECTORY_SEPARATOR . $this->uuid . 'chains.pem';
                        $interFile = $ocspDir . DIRECTORY_SEPARATOR . $this->uuid . 'inter.pem';
                        $siteFile = $ocspDir . DIRECTORY_SEPARATOR . $this->uuid . 'site.pem';
                        file_put_contents($siteFile,trim($sitePem));
                        file_put_contents($interFile,trim(implode("",$interPem)));
                        file_put_contents($chainFile,trim(implode("",$chainsPem)));

                        $ocspHost = parse_url($uri, PHP_URL_HOST);
                        $result['ocspUri'] = $uri;

                        $cmd = 'timeout %d  openssl ocsp -resp_text -no_nonce -CAfile %s -issuer %s -cert %s -url "%s" -header HOST %s 2>&1';
                        $realCmd = sprintf($cmd,
                            $this->timeout,$chainFile,$interFile,$siteFile,
                            escapeshellcmd($uri),escapeshellcmd($ocspHost));
                        $output = shell_exec($realCmd);
                        @unlink($siteFile);
                        @unlink($interFile);
                        @unlink($chainFile);
                        $matches = [];
                        $outs = [];
                        if(preg_match_all('/[ \t\f]*(.*?)\:[ \t\f]+(.*)$/xmD',$output,$matches)) {
                            if (count($matches) == 3) {
                                foreach($matches[1] as $k => $name) {
                                    $outs[$name] = trim($matches[2][$k]);
                                }

                            }
                        }
                        if (isset($outs[$siteFile])) {
                            $status = $outs[$siteFile];
                            if ($status == 'good') {
                                $result["status"] = "success";
                                $result['response'] = preg_match('/Response verify OK/',$output)? "success":"failed";
                            }
                            else if ( $status == "revoked") {
                                $result["status"] = "revoked";
                                $this->warnings[] =  "Certificate revoked on OCSP: " . $uri . ". Revocation time: " . $outs["Revocation Time"] . ".";
                            } else {
                                $result["status"] = "unkown";
                                $this->warnings[] =  "OCSP error on: " . $uri . ".";
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
                    $result["errorMessage"] = "Local Root CA cert not provided. Unable to send OCSP request.";
                }
                if (empty($ocspUris['CA Issuers'])) {
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

    public function parseCertificateByShell($chains, $startKey=0,$nextKey=null,$host=null, $validate_hostname=false, $port="443", $include_chain=null) {

        if (!$this->canExeShell) {
            return null;
        }
        $today = date("Y-m-d");
        $chain = $chains[$startKey];
        $pem = $chain['pem'];
        $source = $chain['source'];
        $result = array(
            'certificatePem'=>$pem,
        );
        //cert
        if (isset($source) ) {
            // purposes
            $purposes = array();
            foreach ($source['purposes'] as $key => $purpose) {
                $purposes[$purpose[2]]["ca"] = $purpose[1];
                $purposes[$purpose[2]]["general"] = $purpose[0];
            }
            unset($source['purposes']);
            $source['purposes'] = $purposes;
            $result["certData"] = $source;
        }
        //ocsp
        $result['ocsp'] = $this->parseOCSPByShell($chains,$startKey);
        // valid from
        if ( !empty($result['certData']['validFrom_time_t']) ) {
            if ( $today < date(DATE_RFC2822,$result['certData']['validFrom_time_t']) ) {
                $result['certIssuedInFuture'] = false;
            } else {
                $result['certIssuedInFuture'] = true;
                $this->warnings[] =  "Certificate issue date is in the future: " . date(DATE_RFC2822,$result['certData']['validFrom_time_t']);
            }
        }
        // expired
        if (!empty($source['validTo_time_t'])) {
            if ($today > date(DATE_RFC2822,$source['validFrom_time_t']) || strtotime($today) < strtotime(date(DATE_RFC2822,$source['validTo_time_t']))) {
                $result['certExpired'] = false;
            } else {
                $result['certExpired'] = true;
                $this->warnings[] =  "Certificate expired! Expiration date: " . date(DATE_RFC2822,$source['validTo_time_t']);
            }
        }
        // almost expired
        if (!empty($source['validTo_time_t'])) {
            $certExpiryDate = strtotime(date(DATE_RFC2822,$source['validTo_time_t']));
            $certExpiryDiff = $certExpiryDate - strtotime($today);
            if ($certExpiryDiff < 2592000) {
                $result['certExpiresInLessThanThirtyDays'] = true;
                $this->warnings[] =  "Certificate expires in " 
                    . round($certExpiryDiff / 84600) . " days!. Expiration date: " 
                    . date(DATE_RFC2822,$certExpiryDate);
            } else {
                $result['certExpiresInLessThanThirtyDays'] = false;
            }
        }

        if (isset($source['extensions']['certificatePolicies'])) {
            $policies = explode("\n", $source['extensions']['certificatePolicies']);
            if (isset($policies[0])) {
                $realPolicies = explode("Policy: ", $policies[0]);
                if (isset($realPolicies[1])) {
                    if (array_search($realPolicies[1], $this->evOids)) {
                        $result["validation_type"] = "extended";
                    }
                }
            }
        } else if ( isset($source['subject']['O'] ) ) {
            $result["validation_type"] = "organization";
        } else if ( isset($source['subject']['CN'] ) ) {
            $result["validation_type"] = "domain";
        }
        // issuer
        $nextSource = $nextChain = null;
        if ($nextKey && isset($chains[$nextKey])) {
            $nextChain = $chains[$nextKey];
            $nextSource = $chains[$nextKey]['source'];
        }
        if ($nextSource) {
            if ($this->verifyCertIssuerBySubjectHashWithShell($chain, $nextChain) ) {
                $result["issuer_valid"] = true;
            } else {
                $result["issuer_valid"] = false;
                $this->warnings[] =  "Provided certificate issuer does not match issuer in certificate. Sent chain order wrong.";
            }
        }
        // crl
        if (isset($source['extensions']['crlDistributionPoints']) ) {
            $result["crl"] = $this->crlVerifyByShell($source);
            if (is_array($result["crl"])) {
                if (isset($result['crl']['revoked']) && $result['crl']['revoked']) {
                    $this->warnings[] =  "Certificate revoked on CRL: " . $result["crl"]['uri']
                        . ". Revocation time: " . $result["crl"]['Revocation Date'] . ".";
                }
            }
        } else {
            $result["crl"] = "No CRL URI found in certificate";
        }

        // hostname validation
        if ($validate_hostname == true) {
            $result["hostname_checked"] = $host;
            if (isset($source['subject']['CN'])) {
                if ( $this->verifyCertificateHostname($source) ) {
                    $result["hostname_in_san_or_cn"] = "true";
                } else {
                    $result["hostname_in_san_or_cn"] = "false";
                    $this->warnings[] =  "Hostname " . $host . " not found in certificate.";
                }
            }
        } else {
            $result["hostname_in_san_or_cn"] = "n/a; ca signing certificate";
        }
        //serial number
        if ( isset($source['serialNumber']) ) {
            $serial = [];
            $sn = str_split(strtoupper($this->bcdechex($source['serialNumber'])), 2);
            $sn_len = count($sn);
            foreach ($sn as $key => $s) {
                $serial[] = htmlspecialchars($s);
                if ( $key != $sn_len - 1) {
                    $serial[] = ":";
                }
            }
            $result["serialNumber"] = implode("", $serial);
        }

        // key details
        $keyDetails = openssl_pkey_get_details(openssl_pkey_get_public($pem));

        // save pem. this because the reconstruct chain function works better
        // this way. not all certs have authorityinfoaccess. We first check if
        // we already have a matching cert.
        $hashDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'crt_hash';
        $this->mkdir($hashDir);
        // filenames of saved certs are hashes of the asort full subject.
        $crt_hash = hash("sha256", $this->formatSubject($source['subject']));
        $crtHashFile = $hashDir . DIRECTORY_SEPARATOR . $crt_hash . ".pem";
        if($this->fileExpired($crtHashFile)) {
            // file older than 5 days. crt might have changed, retry.
            file_put_contents($crtHashFile, $pem);
        }

        $this->checkCertificateFileSize($crtHashFile);

        //chain reconstruction
        if($include_chain && $pem) {
            $construction = $this->chainConstruction($source,$pem);
            $result = array_merge_recursive($result,$construction);
        }

        //hashes
        $string = $pem;
        $pattern = '/-----(.*)-----/';
        $replacement = '';
        $string = preg_replace($pattern, $replacement, $string);

        $pattern = '/\n/';
        $replacement = '';
        $exportPemPreg = preg_replace($pattern, $replacement, $string);
        $exportPemPreg = wordwrap($exportPemPreg, 77, "\n", TRUE);
        $result['hash']['md5'] = $this->certHash('md5',       $exportPemPreg);
        $result['hash']['sha1'] = $this->certHash('sha1',     $exportPemPreg);
        $result['hash']['sha256'] = $this->certHash('sha256', $exportPemPreg);
        $result['hash']['sha384'] = $this->certHash('sha384', $exportPemPreg);
        $result['hash']['sha512'] = $this->certHash('sha512', $exportPemPreg);

        //TLSA check
        if (!empty($source['subject']['CN']) && !empty($host)) {
            if ($validate_hostname == true) {
                $tlsa_record = shell_exec("timeout " . $this->timeout . " dig +short +dnssec +time=" . $this->timeout . " TLSA _" . escapeshellcmd($port) . "._tcp." . escapeshellcmd($host) . " 2>&1 | head -n 1");
                if (!empty($tlsa_record)) {
                    $tlsa = explode(" ", $tlsa_record, 4);
                    $pattern = '/ /';
                    $replacement = '';
                    $result['tlsa']['tlsa_hash'] = trim(strtolower(preg_replace($pattern, $replacement, $tlsa[3])));
                    $result['tlsa']['tlsa_usage'] = $tlsa[0];
                    $result['tlsa']['tlsa_selector'] = $tlsa[1];
                    $result['tlsa']['tlsa_matching_type'] = $tlsa[2];
                    $result['tlsa']['error'] = 'none';
                } else {

                    $result['tlsa']['error'] = 'No TLSA record found.';
                    $result['tlsa']['example'] = '_'. htmlspecialchars($port) . '._tcp.' . htmlspecialchars($host) . ' IN TLSA 3 0 1 ' . $result['hash']['sha256'] . ';';
                }
            } else {
                $result['tlsa']['error'] = 'CA certificate, TLSA not applicable.';
            }
        }
        if (isset($keyDetails['rsa'])) {
            $result["key"]["type"] = "rsa";
            $result["key"]["bits"] = $keyDetails['bits'];
            if ($keyDetails['bits'] < 2048) {
                $this->warnings[] =  $keyDetails['bits'] . " bit RSA key is not safe. Upgrade to at least 4096 bits.";
            }

            // weak debian key check
            $bin_modulus = $keyDetails['rsa']['n'];
            # blacklist format requires sha1sum of output from "openssl x509 -noout -modulus" including the Modulus= and newline.
            # create the blacklist:
            # https://packages.debian.org/source/squeeze/openssl-blacklist
            # svn co svn://svn.debian.org/pkg-openssl/openssl-blacklist/
            # find openssl-blacklist/trunk/blacklists/ -iname "*.db" -exec cat {} >> unsorted_blacklist.db \;
            # sort -u unsorted_blacklist.db > debian_blacklist.db

            $mod_sha1sum = sha1("Modulus=" . strtoupper(bin2hex($bin_modulus)) . "\n");
            $blacklist_file = fopen($this->debianBlacklistDbFile, 'r');
            $key_in_blacklist = false;
            while (($buffer = fgets($blacklist_file)) !== false) {
                if (strpos($buffer, $mod_sha1sum) !== false) {
                    $key_in_blacklist = true;
                    break;
                }
            }
            fclose($blacklist_file);
            if ($key_in_blacklist == true) {
                $result["key"]["weak_debian_rsa_key"] = "true";
                $this->warnings[] =  "Weak debian key found. Remove this key right now and create a new one.";
            }
        } else if (isset($keyDetails['dsa'])) {
            $result["key"]["type"] = "dsa";
            $result["key"]["bits"] = $keyDetails['bits'];
        } else if (isset($keyDetails['dh'])) {
            $result["key"]["type"] = "dh";
            $result["key"]["bits"] = $keyDetails['bits'];
        } else if (isset($keyDetails['ec'])) {
            $result["key"]["type"] = "ecdsa";
            $result["key"]["bits"] = $keyDetails['bits'];
        } else {
            $result["key"]["type"] = "unknown";
            $result["key"]["bits"] = $keyDetails['bits'];
        }
        // signature algorithm
        $result["key"]["signatureAlgorithm"] = $this->certSignatureAlgorithm($chain['resource']);
        if ($result["key"]["signatureAlgorithm"] == "sha1WithRSAEncryption") {
            $this->warnings[] =  "SHA-1 certificate. Upgrade (re-issue) to SHA-256 or better.";
        }
        if(isset($export_pem)) {
            $result["key"]["certificatePem"] = $pem;
        }
        if(isset($keyDetails['key'])) {
            $result["key"]["publicKeyPem"] = $keyDetails['key'];
            $result["key"]["spki_hash"] = $this->spkiHashByShell($pem);
        }
        return $result;
    }

    public function spkiHashByShell($pem) {
        if (!$this->canExeShell) {
            return null;
        }
        $spkiDir = $this->tmpPath . DIRECTORY_SEPARATOR . 'spki';
        $this->mkdir($spkiDir);
        $pemFile = $spkiDir . DIRECTORY_SEPARATOR . $this->uuid . '.cert_client.pem';
        $keyFile = $spkiDir . DIRECTORY_SEPARATOR . $this->uuid . '.public.key';
        //below command returns the SPKI hash of a public key.
        file_put_contents($pemFile,$pem);
        $cmd = 'timeout %d '
            .'openssl x509 -noout -in %s  -pubkey |'
            .'openssl asn1parse -noout -inform PEM  -out %s |'
            .'openssl dgst -sha256 -binary %s |'
            .'openssl enc -base64 2>&1';
        $output = shell_exec(sprintf($cmd,$this->timeout,$pemFile,$keyFile,$keyFile));
        //remove those files again.
        @unlink($pemFile);
        @unlink($keyFile);
        return(trim(htmlspecialchars($output)));
    }

    public function certSignatureAlgorithm($resource)
    {
        $certRead = openssl_x509_read($resource);
        //if param 3 is FALSE, $out is filled with both the PEM file as wel all the contents of `openssl x509 -noout -text -in cert.pem.
        //we use that to get the signature alg.
        openssl_x509_export($certRead, $out, FALSE);
        $signatureAlgorithm = null;
        if (preg_match('/^\s+Signature Algorithm:\s*(.*)\s*$/m', $out, $match)) {
            $signatureAlgorithm = $match[1];
        }
        return $signatureAlgorithm ;
    }

    public function parseCsrByShell($csr) {
        if (!$this->canExeShell) {
            return null;
        }
        //if csr or cert is pasted in form tis function parses the csr or it send the cert to cert_parse.
        $result = array();
        if (strpos($csr, "BEGIN CERTIFICATE REQUEST") !== false) {
            $certData = openssl_csr_get_public_key($csr);
            $cert_details = openssl_pkey_get_details($certData);
            $cert_key = $cert_details['key'];
            $cert_subject = openssl_csr_get_subject($csr);
            $result["subject"] = $cert_subject;
            $result["key"] = $cert_key;
            $result["details"] = $cert_details;
            if ($cert_details) {
                $result["csr_pem"] = $csr;
                $sans = $this->getSansFromCsrByShell($csr);
                if(count($sans) > 1) {
                    $result["csr_sans"] = $sans;
                }
            }
        } else {
            $result = array("error" => "data not valid csr");
        }
        return $result;
    }
}