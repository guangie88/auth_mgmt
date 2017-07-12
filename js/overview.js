String.prototype.capitalize = function() {
  return this.charAt(0).toUpperCase() + this.slice(1);
}

const catchFn = error => alert(JSON.stringify(error, null, 2));

const app = new Vue({
  // router,
  el: '#app',

  data: {
    // models
    adminTaskCreds: null,
    selectedExchange: null,
    selectedUpdate: { username: null, password: null },
    toAddCreds: null,
    toDeleteUsers: null,
    toUpdateUsers: null,
    users: [],

    // models for error
    errorAddMsg: null,
    errorDeleteMsg: null,
    errorUpdateMsg: null,
    
    addUser() {
      axios.post('/add_mapping', this.toAddCreds)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.reload();
          } else {
            this.errorAddMsg = 'Add user error: ' + resp.data.status;
          }
        })
        .catch(catchFn);
    },

    exchange() {
      axios.post('/exchange', this.selectedUpdate)
        .then(resp => {
          if (resp.data.status == 'ok') {
            this.selectedExchange = resp.data.data;
            this.errorUpdateMsg = null;
          } else {
            this.errorUpdateMsg = 'Invalid retrieval: ' + resp.data.status;
            this.selectedExchange = null;
          }
        })
        .catch(catchFn);
    },

    updateUser() {
      const toUpdateUser = {
        username: this.selectedUpdate.username,
        password: this.selectedUpdate.password,
        creds: this.selectedExchange,
      };

      axios.put('/update_mapping', toUpdateUser)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.reload();
          } else {
            this.errorUpdateMsg = 'Update error: ' + resp.data.status;
          }
        })
        .catch(catchFn);
    },

    deleteUsers() {
      const confirmDeleteUserGroups = _.filter(this.toDeleteUsers, toDeleteUser => toDeleteUser.delete);
      const confirmDeleteUsernames = _.map(confirmDeleteUserGroups, confirmDeleteUserGroup => confirmDeleteUserGroup.username);

      // DELETE has a different API from POST
      axios.delete('/force_delete_mappings', { data: confirmDeleteUsernames, headers: { 'Content-Type': 'application/json' } })
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.reload();
          } else {
            this.errorDeleteMsg = 'Delete user(s) error: ' + resp.data.status;
          }
        })
        .catch(catchFn);
    },

    logout() {
      this.$cookies.remove('token', '/', window.location.hostname);
      window.location.href = '/';
    },
  },

  mounted() {
    axios.get('/info')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.adminTaskCreds = resp.data.data;
        }
      })
      .catch(catchFn);

    axios.get('/get_default_creds')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.toAddCreds = resp.data.data;
        }
      })

    axios.get('/get_users')
      .then(resp => {
        if (resp.data.status == 'ok') {
          this.users = _.sortBy(resp.data.data, user => user);

          this.toDeleteUsers = _.map(this.users, user => {
            return { username: user, delete: false };
          });

          this.toUpdateUsers = _.map(this.users, user => {
            return { username: user, selected: false };
          });
        }
      })
      .catch(catchFn);
  },
});