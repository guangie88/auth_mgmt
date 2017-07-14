const catchFn = error => alert(JSON.stringify(error, null, 2));

const getCurrentUrlWithoutParams = () => {
  return window.location.protocol + '//' + window.location.host + window.location.pathname;
};

Vue.component('creds-listing', {
  props: ['disabled', 'creds'],
  template: `
    <table class="table table-striped table-bordered table-hover">
      <thead class="thead-default">
        <tr>
          <th>Operation keys</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(value, key) in creds">
          <td><span v-text="key"></span></td>
          <td>
            <div class="form-group">
              <!-- boolean -->
              <input v-if="typeof(value) === 'boolean'" :disabled="disabled" type="checkbox" v-model="creds[key]">

              <!-- string -->
              <input class="form-control" v-else-if="typeof(value) === 'string'" :disabled="disabled" type="text" v-model="creds[key]">

              <!-- object -->
              <div v-else-if="value !== null && typeof(value) === 'object'">
                <creds-inner-listing :disabled="disabled" :creds="value"></creds-inner-listing>
              </div>
            </div>
          </td>
        </tr>
      </tbody>
    </table>
  `,
});

Vue.component('creds-inner-listing', {
  props: ['disabled', 'creds'],
  template: `
    <div>
      <div class="form-group" v-for="(value, key) in creds">
        <div class="col-sm-2">
          <label :for="key" v-text="key"></label>
        </div>

        <div class="col-sm-10">
          <!-- boolean -->
          <input :id="key" v-if="typeof(value) === 'boolean'" :disabled="disabled" type="checkbox" v-model="creds[key]">

          <!-- string -->
          <input :id="key" v-else-if="typeof(value) === 'string' && key !== 'password'" class="form-control" :disabled="disabled" type="text" v-model="creds[key]">
          <input :id="key" v-else-if="typeof(value) === 'string' && key === 'password'" class="form-control" :disabled="disabled" type="password" v-model="creds[key]">

          <!-- object -->
          <div v-else-if="value !== null && typeof(value) === 'object'">
            <creds-inner-listing :disabled="disabled" :creds="value"></creds-inner-listing>
          </div>
        </div>
      </div>
    </div>
  `,
})

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

    // model for previous action status
    prevActionMsg: null,
    
    addUser() {
      axios.post('/add_mapping', this.toAddCreds)
        .then(resp => {
          if (resp.data.status == 'ok') {
            window.location.href = getCurrentUrlWithoutParams() + '?add'
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
            window.location.href = getCurrentUrlWithoutParams() + '?update'
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
            window.location.href = getCurrentUrlWithoutParams() + '?delete'
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