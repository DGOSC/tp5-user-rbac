<?php
/******************************************************************************
 * 描述：管理员角色
 * 文件：userRole.php
 * ============================================================================
 * 版权所有 2007-2019 武汉道广科技有限公司，并保留所有权利。
 * 网站地址: http://www.dgosc.com；
 * ----------------------------------------------------------------------------
 * 这不是一个自由软件！您只能在不用于商业目的的前提下对程序代码进行修改和使用；
 * 不允许对程序代码以任何形式任何目的的再发布。
 * ============================================================================
 * 作者: Nginx
 * 日期：2020年12月01日
 * 时间：16:43
 ******************************************************************************/

namespace dgosc\user\rbac\validate;

use think\Validate;

class UserRole extends Validate
{
    protected $rule = [
        'name' => 'require|max:50|unique:gmars\rbac\model\role,name^id'
    ];

    protected $message = [
        'name.require' => '角色名不能为空',
        'name.max' => '角色名不能长于50个字符',
        'name.unique' => '角色名称不能重复'
    ];

}