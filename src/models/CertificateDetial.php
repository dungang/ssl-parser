<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 15:28
 */

namespace dungang\sslparser\models;


class CertificateDetial
{

    /**
     * @var string
     */
    public $purposes;

    /**
     * @var string
     */
    public $purposesCA;

    /**
     * @var string
     */
    public $serial;

    /**
     * @var string
     */
    public $keySizeType;

    /**
     * @var string Weak debian key
     */
    public $weakDebianKey;

    /**
     * @var string
     */
    public $signatureAlgorithm;

    /**
     * @var array
     */
    public $hashes;

    /**
     * @var array
     */
    public $extensions;

    /**
     * @var string
     */
    public $certificatePem;

    /**
     * @var string
     */
    public $publicKeyPem;

}