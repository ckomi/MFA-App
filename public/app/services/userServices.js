angular.module('userServices', [])

.factory('User', function($http) {
    var userFactory = {};

    userFactory.create = function(regData) {
        return $http.post('/api/users', regData);
    };

    userFactory.checkUsername = function(regData) {
        return $http.post('/api/checkusername', regData);
    };

    userFactory.checkEmail = function(regData) {
        return $http.post('/api/checkemail', regData);
    };

    userFactory.checkPhone = function(regData) {
        return $http.post('/api/checkphone', regData);
    };

    userFactory.activateAccount = function(token) {
        return $http.put('/api/activate/' + token);
    };

    userFactory.checkCredentials = function(loginData) {
        return $http.post('/api/resend', loginData);
    };

    userFactory.resendLink = function(username) {
        return $http.put('/api/resend', username);
    };

    userFactory.sendUsername = function(userData) {
        return $http.get('/api/resetusername/' + userData);
    };

    userFactory.sendPassword = function(resetData) {
        return $http.put('/api/resetpassword', resetData);
    };

    userFactory.resetUser = function(token) {
        return $http.get('/api/resetpassword/' + token);
    };

    userFactory.savePassword = function(regData) {
        return $http.put('/api/savepassword', regData);
    };

    userFactory.renewSession = function(username) {
        return $http.get('/api/renewToken/' + username);
    };

    userFactory.getPermission = function() {
        return $http.get('/api/permission/');
    };

    userFactory.getUsers = function() {
        return $http.get('/api/management/');
    };

    userFactory.getUser = function(id) {
        return $http.get('/api/edit/' + id);
    };

    userFactory.deleteUser = function(username) {
        return $http.delete('/api/management/' + username);
    };

    userFactory.editUser = function(id) {
        return $http.put('/api/edit', id);
    };

    return userFactory;
});