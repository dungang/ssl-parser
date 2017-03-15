<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 15:29
 */

namespace dungang\sslparser\models;


class CertificateValidity
{
    /**
     * @var bool 证书是否过期
     */
    public $isExpired = false;

    /**
     * @var bool 是否在证书吊销列表
     */
    public $onCRL = false;

    /**
     * @var bool 在线证书状态协议,对证书状态进行实时在线验证
     */
    public $onOCSP = false;

    /**
     * @var bool 域名是否有验证通过
     */
    public $hostnameValid = false;

    /**
     * @var string 有效开始日期
     */
    public $validFrom;

    /**
     * @var string 有效结束日期
     */
    public $validUntil;

    public $crl;

    public $ocsp;

    public $hostnameValidation;
}