<?php
/******************************************************************************
 * 描述：管理员权限管理
 * 文件：userPermission.php
 * ============================================================================
 * 版权所有 2007-2019 武汉道广科技有限公司，并保留所有权利。
 * 网站地址: http://www.dgosc.com；
 * ----------------------------------------------------------------------------
 * 这不是一个自由软件！您只能在不用于商业目的的前提下对程序代码进行修改和使用；
 * 不允许对程序代码以任何形式任何目的的再发布。
 * ============================================================================
 * 作者: Nginx
 * 日期：2020年12月01日
 * 时间：09:37
 ******************************************************************************/

namespace dgosc\user\rbac\validate;

use think\Validate;

class UserPermissionValidate extends Validate
{
    protected $rule = [
        'name' => 'require|max:50|unique:dgosc\user\rbac\model\userpermission,name',
        'path' => 'require|max:200|unique:dgosc\user\rbac\model\userpermission,path',
        'category_id' => 'require|number',
        'type' => 'require'
    ];

    protected $message = [
        'name.require' => '权限名不能为空',
        'name.max' => '权限名不能长于50个字符',
        'path.require' => '路径不能为空',
        'path.max' => '路径不能长于200个字符',
        'category_id.require' => '权限分类必须选择',
        'category_id.number' => '权限分类必须是数字id',
        'name.unique' => '权限名称不能重复',
        'path.unique' => '权限路径不能为空',
        'type.require' => '权限类型不能为空'
    ];

}