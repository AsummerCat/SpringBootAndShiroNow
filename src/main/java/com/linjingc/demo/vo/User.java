package com.linjingc.demo.vo;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;
import java.util.Set;

/**
 * @author cxc
 * @date 2018/10/12 09:16
 */
@Data
@ToString
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private String username;
    private String password;
    private Integer age;
    private Set roles;
    private String salt;
}
