angular.module('managementController', [])

.controller('managementCtrl', function(User, $scope) {
    var app = this;
    app.loading = true;
    app.accessDenied = true;
    app.errorMsg = false;
    app.editAccess = false;
    app.deleteAccess = false;
    app.limit = 5;
    app.searchLimit = 0;

    function getUsers() {
        User.getUsers().then(function(data) {
            if (data.data.success) {
                if (data.data.permission === 'admin' || data.data.permission === 'moderator') {
                    app.users = data.data.users;
                    app.loading = false;
                    app.accessDenied = false;
                    if (data.data.permission === 'admin') {
                        app.editAccess = true;
                        app.deleteAccess = true;
                    } else if (data.data.permission === 'moderator') {
                        app.editAccess = true;
                    }
                } else {
                    app.errorMsg = 'Insufficient Permissions';
                    app.loading = false;
                }
            } else {
                app.errorMsg = data.data.message;
                app.loading = false;
            }
        });
    }
    getUsers();

    app.showMore = function(number) {
        app.showMoreError = false;
        if (number > 0) {
            app.limit = number;
        } else {
            app.showMoreError = 'Please enter a valid number';
        }
    };

    app.showAll = function() {
        app.limit = undefined;
        app.showMoreError = false;
    };

    app.deleteUser = function(username) {
        User.deleteUser(username).then(function(data) {
            if (data.data.success) {
                getUsers();
            } else {
                app.showMoreError = data.data.message;
            }
        });
    };

    app.search = function(searchKeyword, number) {
        if (searchKeyword) {
            if (searchKeyword.length > 0) {
                app.limit = 0;
                $scope.searchFilter = searchKeyword;
                app.limit = number;
            } else {
                $scope.searchFilter = undefined;
                app.limit = 0;
            }
        } else {
            $scope.searchFilter = undefined;
            app.limit = 0;
        }
    };

    app.clear = function() {
        $scope.number = 'Clear';
        app.limit = 0;
        $scope.searchKeyword = undefined;
        $scope.searchFilter = undefined;
        app.showMoreError = false;
    };

    app.advancedSearch = function(searchByUsername, searchByEmail, searchByName) {
        if (searchByUsername || searchByEmail || searchByName) {
            $scope.advancedSearchFilter = {};
            if (searchByUsername) {
                $scope.advancedSearchFilter.username = searchByUsername;
            }
            if (searchByEmail) {
                $scope.advancedSearchFilter.email = searchByEmail;
            }
            if (searchByName) {
                $scope.advancedSearchFilter.name = searchByName;
            }
            app.searchLimit = undefined;
        }
    };

    app.sortOrder = function(order) {
        app.sort = order;
    };
})

.controller('editCtrl', function($scope, $routeParams, User, $timeout) {
    var app = this;
    $scope.nameTab = 'actived';
    app.phase1 = true;
    User.getUser($routeParams.id).then(function(data) {
        if (data.data.success) {
            $scope.newName = data.data.user.name;
            $scope.newPhone = data.data.user.phone;
            $scope.newEmail = data.data.user.email;
            $scope.newUsername = data.data.user.username;
            $scope.newPermission = data.data.user.permission;
            app.currentUser = data.data.user._id;
        } else {
            app.errorMsg = data.data.message;
            $scope.alert = 'alert alert-danger';
        }
    });

    app.namePhase = function() {
        $scope.nameTab = 'actived';
        $scope.usernameTab = 'default';
        $scope.emailTab = 'default';
        $scope.phoneTab = 'default';
        $scope.permissionsTab = 'default';
        app.phase1 = true;
        app.phase2 = false;
        app.phase3 = false;
        app.phase4 = false;
        app.phase5 = false;
        app.errorMsg = false;
    };

    app.usernamePhase = function() {
        $scope.nameTab = 'default';
        $scope.usernameTab = 'actived';
        $scope.emailTab = 'default';
        $scope.phoneTab = 'default';
        $scope.permissionsTab = 'default';
        app.phase1 = false;
        app.phase2 = true;
        app.phase3 = false;
        app.phase4 = false;
        app.phase5 = false;
        app.errorMsg = false;
    };

    app.emailPhase = function() {
        $scope.nameTab = 'default';
        $scope.usernameTab = 'default';
        $scope.emailTab = 'actived';
        $scope.phoneTab = 'default';
        $scope.permissionsTab = 'default';
        app.phase1 = false;
        app.phase2 = false;
        app.phase3 = true;
        app.phase4 = false;
        app.phase5 = false;
        app.errorMsg = false;
    };

    app.phonePhase = function() {
        $scope.nameTab = 'default';
        $scope.usernameTab = 'default';
        $scope.emailTab = 'default';
        $scope.phoneTab = 'actived';
        $scope.permissionsTab = 'default';
        app.phase1 = false;
        app.phase2 = false;
        app.phase3 = false;
        app.phase4 = true;
        app.phase5 = false;
        app.errorMsg = false;
    };

    app.permissionsPhase = function() {
        $scope.nameTab = 'default';
        $scope.usernameTab = 'default';
        $scope.emailTab = 'default';
        $scope.phoneTab = 'default';
        $scope.permissionsTab = 'actived';
        app.phase1 = false;
        app.phase2 = false;
        app.phase3 = false;
        app.phase4 = false;
        app.phase5 = true;
        app.disableUser = false;
        app.disableModerator = false;
        app.disableAdmin = false;
        app.errorMsg = false;
        if ($scope.newPermission === 'user') {
            app.disableUser = true;
        } else if ($scope.newPermission === 'moderator') {
            app.disableModerator = true;
        } else if ($scope.newPermission === 'admin') {
            app.disableAdmin = true;
        }
    };


    app.updateName = function(newName, valid) {
        app.errorMsg = false;
        app.disabled = true;
        if (valid) {
            var userObject = {};
            userObject._id = app.currentUser;
            userObject.name = $scope.newName;
            User.editUser(userObject).then(function(data) {
                if (data.data.success) {
                    $scope.alert = 'alert alert-success';
                    app.successMsg = data.data.message;
                    $timeout(function() {
                        app.nameForm.name.$setPristine();
                        app.nameForm.name.$setUntouched();
                        app.successMsg = false;
                        app.disabled = false;
                    }, 2000);
                } else {
                    $scope.alert = 'alert alert-danger';
                    app.errorMsg = data.data.message;
                    app.disabled = false;
                }
            });
        } else {
            $scope.alert = 'alert alert-danger';
            app.errorMsg = 'Please ensure form is filled out properly';
            app.disabled = false;
        }
    };

    app.updateUsername = function(newUsername, valid) {
        app.errorMsg = false;
        app.disabled = true;
        if (valid) {
            var userObject = {};
            userObject._id = app.currentUser;
            userObject.username = $scope.newUsername;
            User.editUser(userObject).then(function(data) {
                if (data.data.success) {
                    $scope.alert = 'alert alert-success';
                    app.successMsg = data.data.message;
                    $timeout(function() {
                        app.usernameForm.username.$setPristine();
                        app.usernameForm.username.$setUntouched();
                        app.successMsg = false;
                        app.disabled = false;
                    }, 2000);
                } else {
                    app.errorMsg = data.data.message;
                    app.disabled = false;
                }
            });
        } else {
            app.errorMsg = 'Please ensure form is filled out properly';
            app.disabled = false;
        }
    };

    app.updateEmail = function(newEmail, valid) {
        app.errorMsg = false;
        app.disabled = true;
        if (valid) {
            var userObject = {};
            userObject._id = app.currentUser;
            userObject.email = $scope.newEmail;
            User.editUser(userObject).then(function(data) {
                if (data.data.success) {
                    $scope.alert = 'alert alert-success';
                    app.successMsg = data.data.message;
                    $timeout(function() {
                        app.emailForm.email.$setPristine();
                        app.emailForm.email.$setUntouched();
                        app.successMsg = false;
                        app.disabled = false;
                    }, 2000);
                } else {
                    $scope.alert = 'alert alert-danger';
                    app.errorMsg = data.data.message;
                    app.disabled = false;
                }
            });
        } else {
            $scope.alert = 'alert alert-danger';
            app.errorMsg = 'Please ensure form is filled out properly';
            app.disabled = false;
        }
    };

    app.updatePhone = function(newPhone, valid) {
        app.errorMsg = false;
        app.disabled = true;
        if (valid) {
            var userObject = {};
            userObject._id = app.currentUser;
            userObject.phone = $scope.newPhone;
            User.editUser(userObject).then(function(data) {
                if (data.data.success) {
                    $scope.alert = 'alert alert-success';
                    app.successMsg = data.data.message;
                    $timeout(function() {
                        app.phoneForm.phone.$setPristine();
                        app.phoneForm.phone.$setUntouched();
                        app.successMsg = false;
                        app.disabled = false;
                    }, 2000);
                } else {
                    $scope.alert = 'alert alert-danger';
                    app.errorMsg = data.data.message;
                    app.disabled = false;
                }
            });
        } else {
            $scope.alert = 'alert alert-danger';
            app.errorMsg = 'Please ensure form is filled out properly';
            app.disabled = false;
        }
    };

    app.updatePermissions = function(newPermission) {
        app.errorMsg = false;
        app.disableUser = true;
        app.disableModerator = true;
        app.disableAdmin = true;
        var userObject = {};
        userObject._id = app.currentUser;
        userObject.permission = newPermission;
        User.editUser(userObject).then(function(data) {
            if (data.data.success) {
                $scope.alert = 'alert alert-success';
                app.successMsg = data.data.message;
                $timeout(function() {
                    app.successMsg = false;
                    $scope.newPermission = newPermission;
                    if (newPermission === 'user') {
                        app.disableUser = true;
                        app.disableModerator = false;
                        app.disableAdmin = false;
                    } else if (newPermission === 'moderator') {
                        app.disableModerator = true;
                        app.disableUser = false;
                        app.disableAdmin = false;
                    } else if (newPermission === 'admin') {
                        app.disableAdmin = true;
                        app.disableModerator = false;
                        app.disableUser = false;
                    }
                }, 2000);
            } else {
                $scope.alert = 'alert alert-danger';
                app.errorMsg = data.data.message;
                app.disabled = false;
            }
        });
    };
});