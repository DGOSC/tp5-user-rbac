

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for user_permission
-- ----------------------------
DROP TABLE IF EXISTS `###user_permission`;
CREATE TABLE `###user_permission` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增',
  `parent_id` int(11) NOT NULL COMMENT '父系菜单，默认根菜单',
  `type` smallint(4) unsigned NOT NULL DEFAULT '0' COMMENT '权限类型:  1.api权限  2.前路由权限',
  `status` smallint(4) unsigned NOT NULL DEFAULT '0' COMMENT '状态:  0未启用  1正常',
  `name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT '' COMMENT '权限节点名称',
  `list_order` float DEFAULT '10000' COMMENT '排序',
  `app` varchar(40) DEFAULT NULL COMMENT '应用名',
  `icon` varchar(32) DEFAULT NULL COMMENT '栏目图标',
  `category_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '权限分组id',
  `category_level` smallint(4) NOT NULL COMMENT '菜单级别 1 为 1级菜单 2 二级菜单 3 为三级菜单 ',
  `category_name` varchar(32) NOT NULL COMMENT '菜单分组',
  `path` varchar(100) NOT NULL DEFAULT '' COMMENT '权限路径',
  `path_id` varchar(100) NOT NULL DEFAULT '' COMMENT '路径唯一编码',
  `description` varchar(200) NOT NULL DEFAULT '' COMMENT '描述信息',
  `create_time` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '创建时间',
  PRIMARY KEY (`id`),
  KEY `idx_permission` (`path_id`,`status`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='管理员权限节点';

-- ----------------------------
-- Table structure for user_permission_category
-- ----------------------------
DROP TABLE IF EXISTS `###user_permission_category`;
CREATE TABLE `###user_permission_category` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '' COMMENT '权限分组名称',
  `description` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL DEFAULT '' COMMENT '权限分组描述',
  `status` smallint(4) unsigned NOT NULL DEFAULT '1' COMMENT '权限分组状态1有效2无效',
  `create_time` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '权限分组创建时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci COMMENT='管理员权限节点分组表';

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `###user_role`;
CREATE TABLE `###user_role` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL DEFAULT '' COMMENT '角色名',
  `description` varchar(200) NOT NULL DEFAULT '' COMMENT '角色描述',
  `status` smallint(4) unsigned NOT NULL DEFAULT '0' COMMENT '状态1正常0未启用',
  `sort_num` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '排序值',
  PRIMARY KEY (`id`),
  KEY `idx_role` (`status`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='管理员角色';

-- ----------------------------
-- Table structure for user_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `###user_role_permission`;
CREATE TABLE `###user_role_permission` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `role_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '角色编号',
  `permission_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '权限编号',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=39 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='管理员角色权限对应表';

-- ----------------------------
-- Table structure for user_user
-- ----------------------------
DROP TABLE IF EXISTS `###user_user`;
CREATE TABLE `###user_user` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `auzcode` varchar(15) DEFAULT NULL COMMENT '系统登录授权码',
  `avatar_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '头像',
  `nickname` varchar(255) DEFAULT NULL COMMENT '昵称',
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL DEFAULT '' COMMENT '用户名',
  `sex` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '性别',
  `password` varchar(64) NOT NULL DEFAULT '' COMMENT '用户密码',
  `mobile` varchar(20) NOT NULL DEFAULT '' COMMENT '手机号码',
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '邮箱登录',
  `remarks` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '账号备注',
  `status` smallint(4) unsigned NOT NULL DEFAULT '0' COMMENT '状态0禁用1正常',
  `create_time` varchar(255) NOT NULL DEFAULT '0' COMMENT '账号创建时间',
  `update_time` varchar(255) NOT NULL DEFAULT '0' COMMENT '信息更新时间',
  `last_login_time` varchar(255) NOT NULL COMMENT '最后一次登录时间',
  `last_ip_address` varchar(255) DEFAULT NULL COMMENT '最后一次登录的IP地址',
  PRIMARY KEY (`id`),
  KEY `idx_user` (`username`,`mobile`,`status`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='管理员用户表';

-- ----------------------------
-- Table structure for user_user_role
-- ----------------------------
DROP TABLE IF EXISTS `###user_user_role`;
CREATE TABLE `###user_user_role` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `user_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '用户id',
  `role_id` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '角色id',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='管理员用户角色对应关系';

