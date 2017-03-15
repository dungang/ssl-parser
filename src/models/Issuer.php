<?php
/**
 * Author: dungang
 * Date: 2017/3/15
 * Time: 15:21
 */

namespace dungang\sslparser\models;


class Issuer
{
    /**
     * @var string 国家名称
     */
    public $country;

    /**
     * @var string 组织名称
     */
    public $organization;

    /**
     * @var string 主名
     */
    public $commonName;
}