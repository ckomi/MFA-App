angular.module('userControllers', ['userServices'])

.controller('regCtrl', function($http, $location, $timeout, User, $scope) {

    var app = this;

    this.regUser = function(regData, valid, confirmed) {
        app.disabled = true;
        app.loading = true;
        app.errorMsg = false;
        if (valid && confirmed) {
            app.regData.name = app.regData.firstName + " " + app.regData.lastName;
            User.create(app.regData).then(function(data) {
                if (data.data.success) {
                    app.loading = false;
                    $scope.alert = 'alert alert-success';
                    app.successMsg = data.data.message;
                    $timeout(function() {
                        $location.path('/login');
                    }, 2000);
                } else {
                    app.loading = false;
                    app.disabled = false;
                    $scope.alert = 'alert alert-danger';
                    app.errorMsg = data.data.message;
                }
            });
        } else {
            app.disabled = false;
            app.loading = false;
            $scope.alert = 'alert alert-danger';
            app.errorMsg = 'Please ensure form is filled our properly';
        }
    };

    this.checkPhone = function(regData) {
        app.checkingPhone = true;
        app.phoneMsg = false;
        app.phoneInvalid = false;
        User.checkPhone(app.regData).then(function(data) {
            if (data.data.success) {
                app.checkingPhone = false;
                app.phoneMsg = data.data.message;
            } else {
                app.checkingPhone = false;
                app.phoneInvalid = true;
                app.phoneMsg = data.data.message;
            }
        });
    };

    this.checkUsername = function(regData) {
        app.checkingUsername = true;
        app.usernameMsg = false;
        app.usernameInvalid = false;
        User.checkUsername(app.regData).then(function(data) {
            if (data.data.success) {
                app.checkingUsername = false;
                app.usernameMsg = data.data.message;
            } else {
                app.checkingUsername = false;
                app.usernameInvalid = true;
                app.usernameMsg = data.data.message;
            }
        });
    };

    this.checkEmail = function(regData) {
        app.checkingEmail = true;
        app.emailMsg = false;
        app.emailInvalid = false;
        User.checkEmail(app.regData).then(function(data) {
            if (data.data.success) {
                app.checkingEmail = false;
                app.emailMsg = data.data.message;
            } else {
                app.checkingEmail = false;
                app.emailInvalid = true;
                app.emailMsg = data.data.message;
            }
        });
    };
})

.directive('match', function() {
    return {
        restrict: 'A',
        controller: function($scope) {
            $scope.confirmed = false;
            $scope.doConfirm = function(values) {
                values.forEach(function(ele) {
                    if ($scope.confirm == ele) {
                        $scope.confirmed = true;
                    } else {
                        $scope.confirmed = false;
                    }
                });
            };
        },

        link: function(scope, element, attrs) {
            attrs.$observe('match', function() {
                scope.matches = JSON.parse(attrs.match);
                scope.doConfirm(scope.matches);
            });
            scope.$watch('confirm', function() {
                scope.matches = JSON.parse(attrs.match);
                scope.doConfirm(scope.matches);
            });
        }
    };
})