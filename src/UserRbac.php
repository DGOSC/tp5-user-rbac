<?php
/******************************************************************************
 * 描述：后台管理RBAC
 * 文件：userRbac.php
 * ============================================================================
 * 版权所有 2007-2019 武汉道广科技有限公司，并保留所有权利。
 * 网站地址: http://www.dgosc.com；
 * ----------------------------------------------------------------------------
 * 这不是一个自由软件！您只能在不用于商业目的的前提下对程序代码进行修改和使用；
 * 不允许对程序代码以任何形式任何目的的再发布。
 * ============================================================================
 * 作者: fengqing7211
 * 日期：2020年12月01日
 * 时间：09:15
 ******************************************************************************/

namespace  dgosc\user\rbac;

use dgosc\user\rbac\model\UserPermission;
use dgosc\nestedsets\NestedSets;
use dgosc\user\rbac\model\UserPermissionCategory;
use dgosc\user\rbac\model\UserRole;
use dgosc\user\rbac\model\UserUserRole;

use think\Db;
use think\db\Query;
use think\db\Where;
use think\Exception;
use think\facade\Cache;
use think\facade\Request;
use think\facade\Session;

class UserRbac
{
    private $type = "service";
    private $db = '';
    private $saltToken = 'asdfqet9#$@#GS#$%080asdfaasdg';
    private $tokenKey = 'Authorization';

    /**
     * userRbac constructor.
     */
    public function __construct()
    {
        $rbacConfig = config('rbac');
        if (!empty($rbacConfig)) {
            isset($rbacConfig['db']) && $this->db = $rbacConfig['db'];
            isset($rbacConfig['type']) && $this->type = $rbacConfig['type'];
            isset($rbacConfig['salt_token']) && $this->saltToken = $rbacConfig['salt_token'];
            isset($rbacConfig['token_key']) && $this->tokenKey = $rbacConfig['token_key'];
        }

    }

    /**
     ***************************************************************************************
     * 描述: 创建数据表
     * 函数: createTable
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 09:34
     * =====================================================================================
     * * @param string $db
     ***************************************************************************************
     */
    public function createTable($db = '')
    {
        $createTable = new userCreateTable();
        $createTable->create($db);
    }

    /**
     ***************************************************************************************
     * 描述: 配置参数
     * 函数: setDb
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 09:35
     * =====================================================================================
     * * @param string $db
     ***************************************************************************************
     */
    public function setDb($db = '')
    {
        $this->db = $db;
    }

    /**
     ***************************************************************************************
     * 描述: 创建权限
     * 函数: createPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:49
     * =====================================================================================
     * @param array $data
     * @return mixed
     * @throws Exception
     ***************************************************************************************
     */
    public function createPermission(array $data = [])
    {
        $model = new userPermission($this->db);
        $model->data($data);
        try{
            $res = $model->savePermission();
            return $res;
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     ***************************************************************************************
     * 描述: 修改权限数据(版本兼容暂时保留建议使用createPermission方法)
     * 函数: editPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:50
     * =====================================================================================
     * * @param array $data
     * @param null $id
     * @return mixed  * @throws Exception
     ***************************************************************************************
     */
    public function editPermission(array $data = [], $id = null)
    {
        if (!empty($id)) {
            $data['id'] = $id;
        }
        try{
            return $this->createPermission($data);
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     ***************************************************************************************
     * 描述: 根据主键删除权限(支持多主键用数组的方式传入)
     * 函数: delPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:52
     * =====================================================================================
     * * @param int $id
     * @return mixed  * @throws Exception
     ***************************************************************************************
     */
    public function delPermission($id = 0)
    {
        $model = new userPermission($this->db);
        try {
            return $model->delPermission($id);
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     ***************************************************************************************
     * 描述: 根据条件删除权限条件请参考tp5 where条件的写法
     * 函数: delPermissionBatch
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:52
     * =====================================================================================
     * * @param $condition
     * @return bool  * @throws Exception
     ***************************************************************************************
     */
    public function delPermissionBatch($condition)
    {
        $model = new userPermission($this->db);
        if ($model->where($condition)->delete() === false) {
            throw new Exception('批量删除数据出错');
        }
        return true;
    }

    /**
     ***************************************************************************************
     * 描述: 根据主键/标准条件来查询权限
     * 函数: getPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:52
     * =====================================================================================
     * * @param $condition
     * @return mixed
     ***************************************************************************************
     */
    public function getPermission($condition)
    {
        $model = new userPermission($this->db);
        return $model->getuserPermission($condition);
    }

    /**
     ***************************************************************************************
     * 描述: 编辑权限分组
     * 函数: savePermissionCategory
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:53
     * =====================================================================================
     * @param array $data
     * @return mixed
     * @throws Exception
     ***************************************************************************************
     */
    public function savePermissionCategory(array $data = [])
    {
        $model = new userPermissionCategory($this->db);
        $model->data($data);
        try{
            $res = $model->saveCategory();
            return $res;
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     ***************************************************************************************
     * 描述: 根据主键删除权限分组(支持多主键用数组的方式传入)
     * 函数: delPermissionCategory
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:54
     * =====================================================================================
     * @param int $id
     * @return mixed
     * @throws Exception
     ***************************************************************************************
     */
    public function delPermissionCategory($id = 0)
    {
        $model = new userPermissionCategory($this->db);
        try {
            $res = $model->delCategory($id);
            return $res;
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }

    /**
     ***************************************************************************************
     * 描述: 获取权限分组
     * 函数: getPermissionCategory
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:54
     * =====================================================================================
     * @param $where
     * @return mixed
     ***************************************************************************************
     */
    public function getPermissionCategory($where)
    {
        $model = new userPermissionCategory($this->db);
        return $model->getCategory($where);
    }

    /**
     ***************************************************************************************
     * 描述: 编辑角色
     * 函数: createRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:55
     * =====================================================================================
     * @param array $data
     * @param string $permissionIds
     * @return mixed
     * @throws Exception
     ***************************************************************************************
     */
    public function createRole(array $data = [], $permissionIds = '')
    {
        $model = new UserRole($this->db);
        $model->data($data);
        try{
            $res = $model->saveRole($permissionIds);
            return $res;
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }

    }

    /**
     ***************************************************************************************
     * 描述: 根据id或标准条件获取角色
     * 函数: getRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:56
     * =====================================================================================
     * @param $condition
     * @param bool $withPermissionId
     * @return mixed
     ***************************************************************************************
     */
    public function getRole($condition, $withPermissionId = true)
    {
        $model = new UserRole($this->db);
        return $model->getUserRole($condition, $withPermissionId);
    }

    /**
     ***************************************************************************************
     * 描述: 删除角色同时将角色权限对应关系删除(注意，会删除角色分配的权限关联数据)
     * 函数: delRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:57
     * =====================================================================================
     * * @param $id
     * @return mixed  * @throws Exception
     ***************************************************************************************
     */
    public function delRole($id)
    {
        $model = new UserRole($this->db);
        try {
            $res = $model->delRole($id);
            return $res;
        } catch (Exception $e) {
            throw new Exception($e->getMessage());
        }
    }


    /**
     ***************************************************************************************
     * 描述: 为用户分配角色
     * 函数: assignUserRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:58
     * =====================================================================================
     * * @param $userId
     * @param array $role
     * @throws Exception
     ***************************************************************************************
     */
    public function assignUserRole($userId, array $role = [])
    {
        if (empty($userId) || empty($role)) {
            throw new Exception('参数错误');
        }
        $model = new UserUserRole($this->db);
        $model->startTrans();
        if ($model->where('user_id', $userId)->delete() === false) {
            $model->rollback();
            throw new Exception('删除用户原有角色出错');
        }
        $UserRole = [];
        foreach ($role as $v)
        {
            $UserRole [] = ['user_id' => $userId, 'role_id' => $v];
        }
        if ($model->saveAll($UserRole) === false) {
            $model->rollback();
            throw new Exception('给用户分配角色出错');
        }
        $model->commit();
        return ;
    }

    /**
     ***************************************************************************************
     * 描述: 删除用户角色
     * 函数: delUserRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:58
     * =====================================================================================
     * * @param $id
     * @return bool  * @throws Exception
     ***************************************************************************************
     */
    public function delUserRole($id)
    {
        if (empty($id)) {
            throw new Exception('参数错误');
        }
        $model = new UserUserRole($this->db);
        if ($model->where('user_id', $id)->delete() === false) {
            throw new Exception('删除用户角色出错');
        }
        return true;
    }

    /**
     ***************************************************************************************
     * 描述: 获取用户权限并缓存
     * 函数: cachePermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 09:59
     * =====================================================================================
     * @param $id
     * @param int $timeOut
     * @return mixed
     * @throws Exception
     ***************************************************************************************
     */
    public function cachePermission($id, $timeOut = 3600)
    {
        if (empty($id)) {
            throw new Exception('参数错误');
        }
        $model = new userPermission($this->db);
        $permission = $model->userPermission($id, $timeOut);
        return $permission;
    }

    /**
     ***************************************************************************************
     * 描述: 检查用户有没有权限执行某操作
     * 函数: can
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:00
     * =====================================================================================
     * @param $path
     * @return bool
     * @throws Exception
     ***************************************************************************************
     */
    public function can($path)
    {
        if ($this->type == 'jwt') {
            $token = Request::header($this->tokenKey);
            if (empty($token)) {
                throw new Exception('未获取到token');
            }
            $permissionList = Cache::get($token);
        } else {
            //获取session中的缓存名
            $cacheName = Session::get('dgosc_user_rbac_permission_name');
            if (empty($cacheName)) {
                throw new Exception('未查询到登录信息');
            }
            $permissionList = Cache::get($cacheName);
        }

        if (empty($permissionList)) {
            throw new Exception('您的登录信息已过期请重新登录');
        }

        if (isset($permissionList[$path]) && !empty($permissionList[$path])) {
            return true;
        }
        return false;
    }

    /**
     ***************************************************************************************
     * 描述: 生成jwt的token
     * 函数: generateToken
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:01
     * =====================================================================================
     * @param $userId
     * @param int    $timeOut
     * @param string $prefix
     * @return array
     ***************************************************************************************
     */
    public function generateToken($userId, $timeOut = 7200, $prefix = '')
    {
        $token = md5($prefix . $this->randCode(32) . $this->saltToken . time());
        $freshTOken = md5($prefix . $this->randCode(32) . $this->saltToken . time());
        $permissionModel = new userPermission($this->db);
        $permission = $permissionModel->getPermissionByuserUserId($userId);
        //无权限时为登录验证用
        if (!empty($permission)) {
            $newPermission = [];
            if (!empty($permission)) {
                foreach ($permission as $k=>$v)
                {
                    $newPermission[$v['path']] = $v;
                }
            }
            Cache::set($token, $newPermission, $timeOut);
        } else {
            //权限为空时token仅仅用作登录身份验证
            Cache::set($token, '', $timeOut);
        }
        Cache::set($freshTOken, $token, $timeOut);
        return [
            'token' => $token,
            'refresh_token' => $freshTOken,
            'expire' => $timeOut
        ];
    }

    /**
     ***************************************************************************************
     * 描述: 刷新token
     * 函数: refreshToken
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:03
     * =====================================================================================
     * * @param $refreshToken
     * @param int    $timeOut
     * @param string $prefix
     * @return array  * @throws Exception
     ***************************************************************************************
     */
    public function refreshToken($refreshToken, $timeOut = 7200, $prefix = '')
    {
        $token = Cache::get($refreshToken);
        if (empty($token)) {
            throw new Exception('refresh_token已经过期');
        }
        $permission = Cache::get($token);
        if (empty($permission)) {
            throw new Exception('token已经过期');
        }
        $token = md5($prefix . $this->randCode(32) . $this->saltToken . time());
        $freshTOken = md5($prefix . $this->randCode(32) . $this->saltToken . time());
        Cache::set($token, $permission, $timeOut);
        Cache::set($freshTOken, $token);
        return [
            'token' => $token,
            'refresh_token' => $freshTOken,
            'expire' => $timeOut
        ];

    }

    /**
     ***************************************************************************************
     * 描述: 生成随机码
     * 函数: randCode
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:04
     * =====================================================================================
     * @param int $length
     * @param string $type
     * @return string
     ***************************************************************************************
     */
    private function randCode($length = 6, $type = 'mix')
    {
        $number = '0123456789';
        $seed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $specialChar = '!@#$%^&*()_+[]|';
        $randRes = "";
        switch ($type) {
            case 'string':
                for ($i = 0; $i < $length; $i++)
                {
                    $randomInt = rand(0, strlen($seed) - 1);
                    $randRes .= $seed{$randomInt};
                }
                break;
            case 'number':
                for ($i = 0; $i < $length; $i++)
                {
                    $randomInt = rand(0, strlen($number) - 1);
                    $randRes .= $number{$randomInt};
                }
                break;
            case 'mix':
                $mix = $number . $seed;
                for ($i = 0; $i < $length; $i++)
                {
                    $randomInt = rand(0, strlen($mix) - 1);
                    $randRes .= $mix{$randomInt};
                }
                break;
            case 'special':
                $special = $number . $seed . $specialChar;
                for ($i = 0; $i < $length; $i++)
                {
                    $randomInt = rand(0, strlen($special) - 1);
                    $randRes .= $special{$randomInt};
                }
                break;
        }
        return $randRes;
    }

    /**
     ***************************************************************************************
     * 描述: 为角色分配权限
     * 函数: assignRolePermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:04
     * =====================================================================================
     * * @param $roleId
     * @param array $permission
     * @throws Exception
     ***************************************************************************************
     */
    public function assignRolePermission($roleId, array $permission = [])
    {
        throw new Exception('该方法已经弃用，请在创建角色时分配权限，调用createRole方法。如果你得项目中依旧想使用此方法请安装v1.3.1版本');
    }

    /**
     ***************************************************************************************
     * 描述: 移动角色
     * 函数: moveRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:05
     * =====================================================================================
     * @param $id
     * @param $parentId
     * @throws Exception
     ***************************************************************************************
     */
    public function moveRole($id, $parentId)
    {
        throw new Exception('新版本中已经弃用角色的可继承关系，请使用用户可分配多个角色替代，如果你得项目中依旧想使用此方法请安装v1.3.1版本');
    }

    /**
     ***************************************************************************************
     * 描述: 修改角色数据
     * 函数: editRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:05
     * =====================================================================================
     * * @param $data
     * @throws Exception
     ***************************************************************************************
     */
    public function editRole($data)
    {
        throw new Exception('请使用createRole方法在data中传入主键，如果你得项目中依旧想使用此方法请安装v1.3.1版本');
    }

    /**
     ***************************************************************************************
     * 描述: 创建用户[建议在自己系统的业务逻辑中实现]
     * 函数: createUser
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月02日 10:05
     * =====================================================================================
     * @param array $data
     * @throws Exception
     ***************************************************************************************
     */
    public function createUser(array $data = [])
    {
        throw new Exception('该方法在新版本中已经废弃，因为用户表的差异比较大请大家自行实现');
    }
}