# Copyright 2014 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from keystoneclient import base
from keystoneclient import exceptions
from keystoneclient.i18n import _
from keystoneclient.v3 import endpoints
from keystoneclient.v3 import projects

OS_EP_FILTER_EXT = 'OS-EP-FILTER'

class EndpointFilterManager(base.Manager):
    """Manager class for manipulating project-endpoint associations."""
    
    def _build_base_url(self, project=None, endpoint=None):
        project_id = base.getid(project)
        endpoint_id = base.getid(endpoint)

        if project_id and endpoint_id:
            api_path = '/projects/%s/endpoints/%s' % (endpoint_id, project_id)
        elif project_id:
            api_path = '/projects/%s/endpoints' % (project_id)
        elif endpoint_id:
            api_path = '/endpoints/%s/projects' % (endpoint_id)
        else:
            msg = _('Must specify a project, an endpoint, or both')
            raise exceptions.ValidationError(msg)

        return '/' + OS_EP_FILTER_EXT + api_path

    def add_endpoint_to_project(self, project, endpoint):
        """Create a project-endpoint association."""
        if not (project and endpoint):
            raise ValueError(_('project and endpoint are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint=endpoint)
        return super(EndpointFilterManager, self)._put(url=base_url)

    def delete_endpoint_from_project(self, project, endpoint):
        """Remove a project-endpoint association."""
        if not (project and endpoint):
            raise ValueError(_('project and endpoint are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint=endpoint)
        return super(EndpointFilterManager, self)._delete(url=base_url)

    def check_endpoint_in_project(self, project, endpoint):
        """Checks if project-endpoint association exist."""
        if not (project and endpoint):
            raise ValueError(_('project and endpoint are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint=endpoint)
        return super(EndpointFilterManager, self)._head(url=base_url)

    def list_endpoints_for_project(self, project):
        """List all endpoints for a given project."""
        if not project:
            raise ValueError(_('project is required'))

        base_url = self._build_base_url(project=project)
        return super(EndpointFilterManager, self)._list(
            base_url,
            endpoints.EndpointManager.collection_key,
            obj_class=endpoints.EndpointManager.resource_class)

    def list_projects_for_endpoint(self, endpoint):
        """List all projects for a given endpoint."""
        if not endpoint:
            raise ValueError(_('endpoint is required'))

        base_url = self._build_base_url(endpoint=endpoint)
        return super(EndpointFilterManager, self)._list(
            base_url,
            projects.ProjectManager.collection_key,
            obj_class=projects.ProjectManager.resource_class)


class EndpointGroupFilter(base.Resource):
    pass


class EndpointGroupFilterManager(base.CrudManager):
    """Manager class for Endpoint Group Filters."""

    resource_class = EndpointGroupFilter
    collection_key = 'endpoint_groups'
    key = 'endpoint_group'
    base_url = OS_EP_FILTER_EXT

    def create(self, name, description=None, filters=None, **kwargs):
        filters = filters if filters else {}

        return super(EndpointGroupFilterManager, self).create(
            name=name,
            description=description,
            filters=filters,
            **kwargs)

    def get(self, endpoint_group):
        return super(EndpointGroupFilterManager, self).get(
            endpoint_group_id=base.getid(endpoint_group))


    def update(self, endpoint_group, name=None, description=None, filters=None, **kwargs):
        return super(EndpointGroupFilterManager, self).update(
            endpoint_group_id=base.getid(endpoint_group),
            name=name,
            description=description,
            filters=filters,
            **kwargs)
   

    def delete(self, endpoint_group):
        return super(EndpointGroupFilterManager, self).delete(
            endpoint_group_id=base.getid(endpoint_group))


    def list(self, **kwargs):
        base_url = self.base_url
        return super(EndpointGroupFilterManager, self).list(base_url=base_url, **kwargs)

    def _build_base_url(self, project=None, endpoint_group=None):
        project_id = base.getid(project)
        endpoint_group_id = base.getid(endpoint_group)

        if project_id and endpoint_group_id:
            api_path = '/endpoint_groups/{0}/projects/{1}'.format(endpoint_group_id,
                                                                  project_id)
        elif project_id:
            api_path = '/projects/{0}/endpoint_groups'.format(project_id)
        elif endpoint_group_id:
            api_path = '/endpoint_groups/{0}/projects'.format(endpoint_group_id)
        else:
            msg = _('Must specify a project, an endpoint_group, or both')
            raise exceptions.ValidationError(msg)

        return '/' + OS_EP_FILTER_EXT + api_path

    def add_endpoint_group_to_project(self, project, endpoint_group):
        """Create a project-endpoint_group association.
        PUT /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}
        """
        if not (project and endpoint_group):
            raise ValueError(_('project and endpoint_group are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint_group=endpoint_group)
        return super(EndpointGroupFilterManager, self)._put(url=base_url)

    def delete_endpoint_group_from_project(self, project, endpoint_group):
        """Remove a project-endpoint_group association.
        DELETE /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}
        """
        if not (project and endpoint_group):
            raise ValueError(_('project and endpoint_group are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint_group=endpoint_group)
        return super(EndpointGroupFilterManager, self)._delete(url=base_url)

    def check_endpoint_group_in_project(self, project, endpoint_group):
        """Checks if project-endpoint_group association exist.
        HEAD /OS-EP-FILTER/endpoint_groups/{endpoint_group_id}/projects/{project_id}
        """
        if not (project and endpoint_group):
            raise ValueError(_('project and endpoint_group are required'))

        base_url = self._build_base_url(project=project,
                                        endpoint_group=endpoint_group)
        return super(EndpointGroupFilterManager, self)._head(url=base_url)

    def list_endpoint_groups_for_project(self, project):
        """List all endpoints for a given project.
        GET /OS-EP-FILTER/projects/{project_id}/endpoint_groups

        """
        if not project:
            raise ValueError(_('project is required'))

        base_url = self._build_base_url(project=project)
        return super(EndpointGroupFilterManager, self)._list(
            base_url,
            self.collection_key,
            obj_class=self.resource_class)