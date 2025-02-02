package cn.iocoder.springboot.lab23.testdemo.service;

import cn.iocoder.springboot.lab23.testdemo.dao.UserDao;
//import org.junit.Assert;
//import org.junit.Test;
//import org.junit.runner.RunWith;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.test.context.junit4.SpringRunner;

import static org.springframework.test.util.AssertionErrors.assertNotNull;
import static org.springframework.test.util.AssertionErrors.assertNull;

//@RunWith(SpringRunner.class)
@SpringBootTest
public class UserServiceTest2 {

    @Autowired
    private UserService userService;
    //18302632210
    @SpyBean
    private UserDao userDao;
    //

    @Test
    public void testAddSuccess() {
        System.out.println("testAddSuccess");
        // Mock UserService 的 exists 方法
        Mockito.when(userDao.selectByUsername("username")).thenReturn(null);

        assertNotNull("注册返回为 null，注册失败",
                userService.add("username", "password"));
    }

    @Test
    public void testAddFailure() {
        System.out.println("testAddFailure");

        assertNull("注册返回为 null，注册失败",
                userService.add("username", "password"));
    }

}
