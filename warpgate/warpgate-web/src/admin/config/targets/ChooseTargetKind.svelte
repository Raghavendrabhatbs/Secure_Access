<script lang="ts">
    import NavListItem from 'common/NavListItem.svelte'
    import { TargetKind } from 'gateway/lib/api'

    const kinds: {
        name: string
        value: TargetKind
        description: string
    }[] = [
        {
            name: 'SSH',
            value: TargetKind.Ssh,
            description: 'Expose access to shell, SFTP and port forwarding',
        },
        {
            name: 'HTTP',
            value: TargetKind.Http,
            description: 'SecureAccess will act as a reverse proxy',
        },
    ]
</script>

<div class="container-max-md">
    <div class="page-summary-bar">
        <h1>add a target</h1>
    </div>

    <div class="narrow-page">
        {#each kinds as kind (kind.value)}
            <NavListItem
                title={kind.name}
                description={kind.description}
                href={`/config/targets/create/${kind.value}`}
            />
        {/each}
    </div>
</div>
