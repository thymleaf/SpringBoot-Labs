package cn.iocoder.springboot.lab23.testdemo.service;

import cn.iocoder.springboot.lab23.testdemo.dao.UserDao;
import cn.iocoder.springboot.lab23.testdemo.dataobject.UserDO;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;

@SpringBootTest
public class UserServiceTest {

    @MockBean
    private UserDao userDao;

    @Autowired
    private UserService userService;

    @Test
    public void testGet() {
        // Mock UserDao 的 selectById 方法
        Mockito.when(userDao.selectById(1)).thenReturn(
                new UserDO().setId(1).setUsername("username:1").setPassword("password:1"));

        // 查询用户
        UserDO user = userService.get(1);

        // 校验结果
        Assertions.assertEquals(1, user.getId(), "编号不匹配");
        Assertions.assertEquals("username:1", user.getUsername(), "用户名不匹配");
        Assertions.assertEquals("password:1", user.getPassword(), "密码不匹配");
    }

}
