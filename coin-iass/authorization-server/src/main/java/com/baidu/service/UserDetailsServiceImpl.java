package com.baidu.service;

import com.baidu.constant.LoginConstant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.dao.IncorrectUpdateSemanticsDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        ServletRequestAttributes requestAttributes = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
        //区分是后台人员还是我们的用户登录
        String loginType = requestAttributes.getRequest().getParameter("login_type");
        if (StringUtils.isEmpty(loginType)){
            throw new AuthenticationServiceException("登录类型不能为null");
        }
        UserDetails userDetails = null;
        try {
            //获取登录的授权率类型
            String grantType = requestAttributes.getRequest().getParameter("grant_type");
            //如果grantType==refresh_token进行纠正
            if(LoginConstant.REFRESH_TOKEN.equals(grantType.toUpperCase(Locale.ROOT))){
                username = adjustUsername(username,loginType);//为refresh_token时，需要将id-》username
            }
            switch (loginType) {
                case LoginConstant.ADMIN_TYPE: // 管理员登录
                    userDetails =  loadSysUserByUsername(username);
                    break;
                case LoginConstant.MEMBER_TYPE: // 会员登录
                    userDetails =  loadMemberUserByUsername(username);
                    break;
                default:
                    throw new AuthenticationServiceException("暂不支持的登录方式" + loginType);
            }
        }catch (IncorrectResultSizeDataAccessException e){  //我们的用户不存在
            throw new UsernameNotFoundException("用户名"+username+"不存在");
        }
        return userDetails;
    }

    //纠正用户的名称
    //username：用户的id
    //loginType：用户的type（member_type）  或者管理员的type（admin_type）
    private String adjustUsername(String username, String loginType) {
        if (LoginConstant.ADMIN_TYPE.equals(loginType)){
            //管理员的纠正方式
            return jdbcTemplate.queryForObject(LoginConstant.QUERY_ADMIN_USER_WITH_ID, String.class, username);
        }
        if (LoginConstant.MEMBER_TYPE.equals(loginType)){
            //会员的纠正方式
            return jdbcTemplate.queryForObject(LoginConstant.QUERY_MEMBER_USER_WITH_ID, String.class, username);
        }
        return username;
    }

    //后台管理人员的登录
    //1.使用用户名查询用户
    //2.查询这个用户对应的权限
    //3.封装成一个UserDetails对应 进行返回
    private UserDetails loadSysUserByUsername(String username) {
        //1.使用用户名查询用户
        return jdbcTemplate.queryForObject(LoginConstant.QUERY_ADMIN_SQL, new RowMapper<User>() {
            @Override
            public User mapRow(ResultSet rs, int rowNum) throws SQLException {
                if (rs.wasNull()){
                    throw new UsernameNotFoundException("用户名"+username+"不存在");
                }
                long id = rs.getLong("id");  //用户的id
                String password = rs.getNString("password");
                int status = rs.getInt("status");
                User user = new User(
                        String.valueOf(id),  //使用id--usename  使用用户id代替username的概念
                        password,  //密码
                        status==1,  //用户的状态 是否被禁用 1 表示没被禁用
                        true,  //用户没有过期
                        true,  //用户没有被锁定
                        true,  //
                        getSysUserPermissions(id) //用户的角色
                );
                return user;
            }
        },username);
    }

    //2.查询这个用户对应的权限
    //通过用户id 查询用户的权限
    private Collection<? extends GrantedAuthority> getSysUserPermissions(long id) {
        //当用户为超级管理员时，它拥有所有的权限数据
        String roleCode = jdbcTemplate.queryForObject(LoginConstant.QUERY_ROLE_CODE_SQL, String.class, id);
        List<String> permissions = null;  //权限的名称
        if (LoginConstant.ADMIN_ROLE_CODE.equals(roleCode)){//超级管理员
            permissions = jdbcTemplate.queryForList(LoginConstant.QUERY_ALL_PERMISSIONS, String.class);
        }else {//普通用户，需要使用角色--->权限数据
            permissions = jdbcTemplate.queryForList(LoginConstant.QUERY_PERMISSION_SQL, String.class, id);
        }
        //如果permissions为空，返回一个空的集合
        if (permissions==null || permissions.isEmpty()){
            return Collections.emptySet();
        }
        //如果permissions有值
        return permissions.stream()
                .distinct()  //去重
                .map(perm->new SimpleGrantedAuthority(perm))
                .collect(Collectors.toSet());
    }

    //会员登录
    private UserDetails loadMemberUserByUsername(String username) {
        return jdbcTemplate.queryForObject(LoginConstant.QUERY_MEMBER_SQL, new RowMapper<User>() {
            @Override
            public User mapRow(ResultSet rs, int rowNum) throws SQLException {
                if (rs.wasNull()){
                    throw new UsernameNotFoundException("用户："+username+"不存在");
                }
                long id = rs.getLong("id");  //用户的id
                String password = rs.getNString("password");
                int status = rs.getInt("status");
                return new User(
                        String.valueOf(id),  //使用id--usename  使用用户id代替username的概念
                        password,  //密码
                        status==1,  //用户的状态 是否被禁用 1 表示没被禁用
                        true,  //用户没有过期
                        true,  //用户没有被锁定
                        true,  //
                        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"))  //权限 会员因为没有权限没有角色，所以默认给一个ROLE_USER
                );
            }
        },username,username);
    }
}