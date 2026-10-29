<script lang="ts">
    import { Alert, Dropdown, DropdownItem, DropdownMenu, DropdownToggle } from '@sveltestrap/sveltestrap'
    import { api, type TargetGroup } from 'admin/lib/api'
    import { adminPermissions } from 'admin/lib/store'
    import { stringifyError } from 'common/errors'
    import EmptyState from 'common/EmptyState.svelte'
    import GroupColorCircle from 'common/GroupColorCircle.svelte'
    import ItemList, { type PaginatedResponse } from 'common/ItemList.svelte'
    import { compare as naturalCompareFactory } from 'natural-orderby'
    import { from, map, type Observable } from 'rxjs'
    import { link, push } from 'svelte-spa-router'

    function getTargetGroups(): Observable<PaginatedResponse<TargetGroup>> {
        return from(api.listTargetGroups()).pipe(
            map(groups => {
                const sorted = groups.sort((a, b) =>
                    naturalCompareFactory()(
                        a.name.toLowerCase(),
                        b.name.toLowerCase(),
                    ),
                )

                return {
                    items: sorted,
                    offset: 0,
                    total: sorted.length,
                }
            }),
        )
    }

    let error: string | undefined = $state()
    let listKey = $state(0)

    async function deleteGroup(group: TargetGroup) {
        if (!confirm(`Delete target group "${group.name}"? Targets in this group will remain but become ungrouped.`)) {
            return
        }
        error = undefined
        try {
            await api.deleteTargetGroup({ id: group.id })
            listKey += 1
        } catch (err) {
            error = await stringifyError(err)
        }
    }
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>target groups</h1>
        <a
            class="btn btn-primary ms-auto"
            href="/config/target-groups/create"
            class:disabled={!$adminPermissions.targetsCreate}
            use:link
        >
            Add a group
        </a>
    </div>

    {#if error}
        <Alert color="danger">{error}</Alert>
    {/if}

    {#key listKey}
    <ItemList load={getTargetGroups} showSearch={true}>
        {#snippet empty()}
            <EmptyState
                title="No target groups yet"
                hint="Target groups help organize your targets for easier management"
            />
        {/snippet}
        {#snippet item(group)}
            <div class="list-group-item group-row">
                <a
                    class="group-link"
                    href="/config/target-groups/{group.id}"
                    use:link
                >
                    <div class="me-auto">
                    <div class="d-flex align-items-center gap-2">
                        {#if group.color}
                            <GroupColorCircle color={group.color} />
                        {/if}
                        <strong>{group.name}</strong>
                    </div>
                    {#if group.description}
                        <small class="d-block text-muted"
                            >{group.description}</small
                        >
                    {/if}
                    </div>
                </a>
                <Dropdown>
                    <DropdownToggle
                        class="row-actions-toggle"
                        aria-label={`Actions for ${group.name}`}
                        title={`Actions for ${group.name}`}
                        caret={false}
                    >
                        ⋯
                    </DropdownToggle>
                    <DropdownMenu end>
                        <DropdownItem
                            disabled={!$adminPermissions.targetsEdit}
                            onclick={() => push(`/config/target-groups/${group.id}`)}
                        >
                            Edit
                        </DropdownItem>
                        <DropdownItem
                            class="text-danger"
                            onclick={() => deleteGroup(group)}
                            disabled={!$adminPermissions.targetsDelete}
                        >
                            Delete
                        </DropdownItem>
                    </DropdownMenu>
                </Dropdown>
            </div>
        {/snippet}
    </ItemList>
    {/key}
</div>

<style lang="scss">
    .group-row {
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .group-link {
        min-width: 0;
        flex: 1;
        color: inherit;
        text-decoration: none;
    }
    :global(.row-actions-toggle) {
        min-width: 34px;
        padding: 2px 8px;
        border: 1px solid var(--bs-border-color);
        color: var(--bs-body-color);
        font-size: 20px;
        line-height: 1.2;
    }
    :global(.row-actions-toggle:hover),
    :global(.row-actions-toggle:focus) {
        background: var(--bs-tertiary-bg);
        color: var(--bs-body-color);
    }
</style>
