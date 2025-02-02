package cn.iocoder.springboot.lab23.testdemo.dao;

import cn.iocoder.springboot.lab23.testdemo.dataobject.UserDO;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

@SpringBootTest
public class UserDaoTest {

    @Autowired
    private UserDao userDao;

    @Test
    @Sql(scripts = "/sql/create_tables.sql", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
    @Sql(statements = "INSERT INTO `t_user`(`id`, `username`, `password`) VALUES (1, 'username:1', 'password:1');", executionPhase = Sql.ExecutionPhase.BEFORE_TEST_METHOD)
    @Sql(scripts = "/sql/clean.sql", executionPhase = Sql.ExecutionPhase.AFTER_TEST_METHOD)
    public void testSelectById() {
        // 查询用户
        UserDO user = userDao.selectById(1);

        System.out.println("testSelectById...");

        // 校验结果
        Assertions.assertEquals(1, user.getId(), "编号不匹配");
        Assertions.assertEquals("username:1", user.getUsername(), "用户名不匹配");
        Assertions.assertEquals("password:1", user.getPassword(), "密码不匹配");
    }

}
