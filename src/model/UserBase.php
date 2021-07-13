<?php
/******************************************************************************
 * 描述：权限管理公共文件
 * 文件：userBase.php
 * ============================================================================
 * 版权所有 2007-2019 武汉道广科技有限公司，并保留所有权利。
 * 网站地址: http://www.dgosc.com；
 * ----------------------------------------------------------------------------
 * 这不是一个自由软件！您只能在不用于商业目的的前提下对程序代码进行修改和使用；
 * 不允许对程序代码以任何形式任何目的的再发布。
 * ============================================================================
 * 作者: Nginx
 * 日期：2020年12月01日
 * 时间：09:42
 ******************************************************************************/
namespace dgosc\user\rbac\model;

use think\Model;

class UserBase extends Model
{
    protected $connection = '';

    public function __construct($db = '', $data = [])
    {
        parent::__construct($data);
        $this->connection = empty($db)? config('rbac')['db'] : $db;
    }

}