<?php
/******************************************************************************
 * 描述：
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
 * 时间：16:48
 ******************************************************************************/

namespace dgosc\user\rbac\model;

use dgosc\user\rbac\validate\UserRoleValidate;
use think\Db;
use think\Exception;

class UserRole extends UserBase
{

    /**
     ***************************************************************************************
     * 描述: 编辑角色
     * 函数: saveRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 16:59
     * =====================================================================================
     * * @param string $permissionIds
     * @param array $data
     * @return $this
     ***************************************************************************************
     */
    public function saveUserRole($permissionIds = '', $data = [])
    {
        if (!empty($data)) {
            $this->data($data);
        }
        $validate = new UserRoleValidate();
        if (!$validate->check($this)) {
            throw new Exception($validate->getError());
        }
        $data = $this->getData();
        if (isset($data['id']) && !empty($data['id'])) {
            $this->isUpdate(true);
        }
        $this->startTrans();
        if ($this->save() === false) {
            $this->rollback();
            throw new Exception('写入角色时出错');
        }
        //如果有权限的情况下
        if (empty($permissionIds)) {
            $this->commit();
            return $this;
        }
        $permissionIdsArr = array_filter(explode(',', $permissionIds));
        if (empty($permissionIdsArr)) {
            $this->commit();
            return $this;
        }
        //删除原有权限
        $rolePermission = new UserRolePermission($this->connection);
        if ($rolePermission->where('role_id', $this->id)->delete() === false) {
            $this->rollback();
            throw new Exception('删除原有权限时出错');
        }
        $writeData = [];
        foreach ($permissionIdsArr as $v)
        {
            $writeData[] = [
                'role_id' => $this->id,
                'permission_id' => $v
            ];
        }
        if ($rolePermission->saveAll($writeData) === false) {
            $this->rollback();
            throw new Exception('写入角色权限时出错');
        }
        $this->commit();
        return $this;
    }

    /**
     ***************************************************************************************
     * 描述: 删除角色
     * 函数: delRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 17:00
     * =====================================================================================
     * * @param $condition
     * @return bool
     ***************************************************************************************
     */
    public function delUserRole($condition)
    {
        $where = [];
        $relationWhere = [];
        if (is_array($condition)) {
            $where[] = ['id', 'IN', $condition];
            $relationWhere[] = ['role_id', 'IN', $condition];
        } else {
            $id = (int)$condition;
            if (is_numeric($id) && $id > 0) {
                $where[] = ['id', '=', $id];
                $relationWhere[] = ['role_id', '=', $condition];
            } else {
                throw new Exception('删除条件错误');
            }
        }
        $this->startTrans();
        if ($this->where($where)->delete() === false) {
            $this->rollback();
            throw new Exception('删除角色出错');
        }
        $rolePermission = new RolePermission($this->connection);
        if ($rolePermission->where($relationWhere)->delete() === false) {
            $this->rollback();
            throw new Exception('删除角色关联权限出错');
        }
        $this->commit();
        return true;
    }

    /**
     ***************************************************************************************
     * 描述: 获取角色列表
     * 函数: getRole
     * =====================================================================================
     * 作者: 武汉道广科技有限公司
     * 邮箱: dgosc@163.com
     * 日期：2020年12月01日 17:01
     * =====================================================================================
     * @param $condition
     * @param false $withPermissionId
     * @return mixed
     ***************************************************************************************
     */
    public function getUserRole($condition, $withPermissionId = false)
    {
        $model = Db::name('user_role')->setConnection($this->getConnection());
        $where = [];
        if (is_array($condition)) {
            $where = $condition;
        } else {
            $condition = (int)$condition;
            if (is_numeric($condition) && $condition > 0) {
                $role = $model->where('id', $condition)->find();
                if (!empty($role) && $withPermissionId) {
                    $role['permission_ids'] = Db::name('user_role_permission')->setConnection($this->getConnection())->where('role_id', $condition)->column('permission_id');
                }
                return $role;
            }
        }
        $role = Db::name('user_role')->setConnection($this->getConnection())->where($where)->select();
        if (!empty($role) && $withPermissionId) {
            $permission = Db::name('user_role_permission')->setConnection($this->getConnection())->where('role_id', 'IN', array_column($role, 'id'))->select();
            $roleIdIndexer = [];
            if (!empty($permission)) {
                foreach ($permission as $v)
                {
                    $roleIdIndexer[$v['role_id']][] = $v['permission_id'];
                }
            }
            foreach ($role as &$v)
            {
                $v['permission_ids'] = isset($roleIdIndexer[$v['id']])? $roleIdIndexer[$v['id']] : [];
                unset($v);
            }
        }
        return $role;
    }

}