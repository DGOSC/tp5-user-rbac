<?php
/******************************************************************************
 * 描述：管理员权限设置
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
 * 时间：09:40
 ******************************************************************************/

namespace dgosc\user\rbac\model;
use think\Db;
use think\Exception;
use think\facade\Cache;
use think\facade\Session;

class UserPermission extends userBase
{

    private $_permissionCachePrefix = "_user_RBAC_PERMISSION_CACHE_";
    protected $auto = ['path_id'];

    protected function setPathIdAttr()
    {
        return md5($this->getData('path'));
    }

    /**
     ***************************************************************************************
     * 描述: 编辑权限数据
     * 函数: saveuserPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 09:48
     * =====================================================================================
     * * @param array $data
     * @return $this
     ***************************************************************************************
     */
    public function saveuserPermission($data = [])
    {
        if (!empty($data)) {
            $this->data($data);
        }
        $validate = new \dgosc\user\rbac\validate\UserPermission();
        if (!$validate->check($this)) {
            throw new Exception($validate->getError());
        }
        $data = $this->getData();
        if (isset($data['id']) && !empty($data['id'])) {
            $this->isUpdate(true);
        }
        $this->save();
        return $this;
    }

    /**
     ***************************************************************************************
     * 描述: 删除权限数据
     * 函数: deluserPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 09:48
     * =====================================================================================
     * * @param $id
     * @return bool
     ***************************************************************************************
     */
    public function delUserPermission($id)
    {
        $where = [];
        if (is_array($id)) {
            $where[] = ['id', 'IN', $id];
        } else {
            $id = (int)$id;
            if (is_numeric($id) && $id > 0) {
                $where[] = ['id', '=', $id];
            } else {
                throw new Exception('删除条件错误');
            }
        }

        if ($this->where($where)->delete() === false) {
            throw new Exception('删除权限出错');
        }
        return true;
    }

    public function UserPermission($userId, $timeOut = 3600)
    {
        if (empty($userId)) {
            throw new Exception('参数错误');
        }
        $permission = Cache::get($this->_permissionCachePrefix . $userId);
        if (!empty($permission)) {
            return $permission;
        }
        $permission = $this->getPermissionByuserId($userId);
        if (empty($permission)) {
            throw new Exception('未查询到该用户的任何权限');
        }
        $newPermission = [];
        if (!empty($permission)) {
            foreach ($permission as $k=>$v)
            {
                $newPermission[$v['path']] = $v;
            }
        }
        Cache::set($this->_permissionCachePrefix . $userId, $newPermission, $timeOut);
        Session::set('dgosc_user_rbac_permission_name', $this->_permissionCachePrefix . $userId);
        return $newPermission;
    }

    /**
     ***************************************************************************************
     * 描述: 根据userid获取权限
     * 函数: getPermissionByuserId
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 16:35
     * =====================================================================================
     * @param $userId
     * @return mixed
     ***************************************************************************************
     */
    public function getPermissionByUserUserId($userId)
    {
        $prefix = $this->getConfig('prefix');
        $permission = Db::name('user_permission')->setConnection($this->getConnection())->alias('p')
            ->join(["{$prefix}user_role_permission" => 'rp'], 'p.id = rp.permission_id')
            ->join(["{$prefix}user_user_role" => 'ur'], 'rp.role_id = ur.role_id')
            ->where('ur.user_id', $userId)->select();
        return $permission;
    }

    /**
     ***************************************************************************************
     * 描述: 获取权限节点
     * 函数: getuserPermission
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 16:36
     * =====================================================================================
     * @param $condition
     * @return mixed
     ***************************************************************************************
     */
    public function getUserPermission($condition)
    {
        $model = Db::name('user_permission')->setConnection($this->getConnection());
        if (is_numeric($condition)) {
            return $model->where('id', $condition)->find();
        } else {
            return $model->where($condition)->select();
        }
    }
}