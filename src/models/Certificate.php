<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 14:44
 */

namespace dungang\sslparser\models;


class Certificate extends Issuer
{
    /**
     * @var string 域名
     */
    public $hostName;

    /**
     * @var string 签名类型 CA / Self
     */
    public $signingType = 'Self';

    /**
     * @var string 组织所在省份
     */
    public $state;

    /**
     * @var string 组织所在城市
     */
    public $city;
    /**
     * @var string 组织所在街道
     */
    public $street;

    /**
     * @var string 邮编
     */
    public $postalCode;

    /**
     * @var string 国家英文
     */
    public $jurisdictionC;

    /**
     * @var string 省份英文
     */
    public $jurisdictionST;

    /**
     * @var string 城市英文
     */
    public $jurisdictionL;

    /**
     * @var string 企业编号，如：组织机构代码等
     */
    public $serialNumber;

    /**
     * @var string 组织单位
     */
    public $organizationUnit;

    /**
     * @var string 组织类型，Organization Validation
     */
    public $type;

    /**
     * @var string 企业商业性质，如：国企，私营等
     */
    public $businessType;

    /**
     * @var string 可选子名列表
     */
    public $subjectAlternativeNames;

    /**
     * @var string 完整的主题信息
     */
    public $fullSubject;

    /**
     * @var Issuer
     */
    public $issuer;

    /**
     * @var CertificateValidity
     */
    public $validity;

    /**
     * @var CertificateDetial
     */
    public $details;

}